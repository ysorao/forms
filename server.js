const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const ldap = require("ldapjs");
const jwt = require("jsonwebtoken");
const sql = require("mssql");
require("dotenv").config();

// Clave secreta para firmar los tokens
const SECRET_KEY = process.env.SECRET_KEY;

// Configuración de la base de datos
const dbConfig = {
    user: process.env.DB_USER, // Usuario de la base de datos
    password: process.env.DB_PASSWORD, // Contraseña de la base de datos
    server: process.env.DB_SERVER, // Dirección del servidor SQL
    database: process.env.DB_DATABASE, // Nombre de la base de datos
    options: {
        encrypt: false, // Usa en Azure, si no estás en Azure puedes ignorar
        trustServerCertificate: false, // Solo si estás trabajando localmente
    },
};


// Función de autenticación LDAP
async function authenticateUser(username, password) {
    return new Promise((resolve, reject) => {
        if (!username || !password) {
            return resolve({
                status: false,
                message: "El usuario y la contraseña no pueden estar en blanco.",
            });
        }

        const ldapServer = process.env.LDAP_SERVER; // Dirección del servidor LDAP
        const baseDN = process.env.LDAP_BASE_DN; // Ajusta al contenedor correcto
        const client = ldap.createClient({ url: ldapServer });

        const ldapUser = `${username}@heon.com.co`; // Formato del usuario

        // Intentar autenticación
        client.bind(ldapUser, password, (err) => {
            if (err) {
                client.unbind();
                return resolve({
                    status: false,
                    message: "Credenciales inválidas o error en la autenticación.",
                });
            }

            // Configurar búsqueda
            const searchOptions = {
                filter: `(&(objectClass=user)(sAMAccountName=${username}))`,
                scope: "sub",
                attributes: ["*"], // Recupera todos los atributos disponibles
            };

            client.search(baseDN, searchOptions, (err, search) => {
                if (err) {
                    client.unbind();
                    return resolve({
                        status: true,
                        message: "Autenticación exitosa, pero no se pudo recuperar información del usuario.",
                    });
                }

                let userData = {};
                search.on("searchEntry", (entry) => {
                    const attributes = entry.attributes.reduce((acc, attr) => {
                        acc[attr.type] = attr.values[0];
                        return acc;
                    }, {});

                    userData = {
                        displayName: attributes.displayName || null,
                        lastName: attributes.sn || null,
                        firstName: attributes.givenName || null,
                        document: attributes.employeeID || null,
                        title: attributes.title || null,
                        fax: attributes.facsimileTelephoneNumber || null,
                        phone: attributes.telephoneNumber || null,
                    };
                });

                search.on("end", () => {
                    client.unbind();

                    if (Object.keys(userData).length > 0) {
                        // Generar el token JWT
                        const token = jwt.sign(
                            { username, userData },
                            SECRET_KEY,
                            { expiresIn: "1h" } // El token expira en 1 hora
                        );

                        return resolve({
                            status: true,
                            message: "Autenticación exitosa.",
                            token, // Enviamos el token al cliente
                        });
                    } else {
                        return resolve({
                            status: true,
                            message: "Autenticación exitosa, pero no se pudo recuperar información del usuario.",
                        });
                    }
                });

                search.on("error", (err) => {
                    client.unbind();
                    return resolve({
                        status: false,
                        message: `Error en la búsqueda LDAP: ${err.message}`,
                    });
                });
            });
        });
    });
}

// Middleware para verificar el token
function verifyToken(req, res, next) {
    const token = req.headers["authorization"]?.split(" ")[1]; // Leer el token del encabezado

    if (!token) {
        return res.status(403).json({ message: "Token requerido." });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Token inválido o expirado." });
        }
        req.user = decoded; // Decodificar el token y adjuntar la información al request
        next();
    });
}

// Crear servidor con Express
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Verificar la conexión al iniciar el servidor
connectToDatabase()
    .then(() => {
        console.log("Conexión a la base de datos verificada al iniciar el servidor.");
    })
    .catch((err) => {
        console.error("Error al verificar la conexión al iniciar el servidor:", err.message);
        process.exit(1); // Detener el servidor si no hay conexión
    });


// Conectar con la base de datos
async function connectToDatabase() {
    try {
        const pool = await sql.connect(dbConfig);
        console.log("Conexión a la base de datos establecida.");
        return pool;
    } catch (err) {
        console.error("Error conectando a la base de datos:", err);
        throw err;
    }
}

// Ruta para comprobar la conexión a la base de datos
app.get("/test-db-connection", async (req, res) => {
    try {
        // Intentar conectar a la base de datos
        const pool = await connectToDatabase();
        // Liberar la conexión después de probarla
        await pool.close();

        res.json({
            status: true,
            message: "Conexión a la base de datos exitosa.",
        });
    } catch (error) {
        console.error("Error probando la conexión a la base de datos:", error);
        res.status(500).json({
            status: false,
            message: "Error conectando a la base de datos: " + error.message,
        });
    }
});


// Ruta para autenticación
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            status: false,
            message: "Usuario y contraseña son requeridos.",
        });
    }

    try {
        const result = await authenticateUser(username, password);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            status: false,
            message: "Error interno del servidor: " + error.message,
        });
    }
});


// Ruta para realizar la consulta y devolver los datos
app.get("/test-access-data", verifyToken, async (req, res) => {
    try {
        // Conectar a la base de datos
        const pool = await connectToDatabase();

        // Ejecutar la consulta
        const result = await pool
            .request()
            .query("select  NOMBRE+ ' ' + APELLIDO AS NOMBRES,EMPLEADO, DPTO FROM [10.99.240.163].[HeonMidasoft].[dbo].[EMP] WHERE NOMBRE LIKE '%OSCAR%' AND ESTADO=''");

        // Devolver los resultados
        res.json({
            status: true,
            data: result.recordset,
        });
    } catch (error) {
        console.error("Error al ejecutar la consulta:", error);
        res.status(500).json({
            status: false,
            message: "Error interno del servidor: " + error.message,
        });
    }
});


// Ruta protegida para "registro"
app.get("/registro", verifyToken, (req, res) => {
    res.json({
        message: "Acceso permitido. Estás autenticado.",
        user: req.user, // Información del usuario del token
    });
});

// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
