const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const session = require('express-session');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();

app.use(bodyParser.urlencoded({ extended: true }));

timezone: 'America/Tijuana'

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

function requireRole(roles) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      next(); 
    } else {
      res.status(403).send('Acceso denegado'); 
    }
  };
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

// Ruta para la página principal
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public')));


// Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(bodyParser.urlencoded({ extended: true }));

// Configuración de MySQL
const connection = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASSWORD,   // Contraseña desde .env
  database: process.env.DB_NAME    // Nombre de la base de datos desde .env
});

// Conectar a la base de datos
connection.connect(err => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos');
});


// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public')));

connection.connect(err => {
  if (err) throw err;
  console.log('Conectado a la base de datos');
});

// Registro de usuario
app.post('/registro', (req, res) => {
  const { username, password, codigo_acceso } = req.body;

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  connection.query(query, [codigo_acceso], (err, results) => {
      if (err || results.length === 0) {
          return res.send('Código de acceso inválido');
      }

      const tipo_usuario = results[0].tipo_usuario;
      const hashedPassword = bcrypt.hashSync(password, 10);

      const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
      connection.query(insertUser, [username, hashedPassword, tipo_usuario], (err) => {
          if (err) return res.send('Error al registrar usuario');
          res.redirect('/login.html');
      });
  });
});

// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password} = req.body;
  const query = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  connection.query(query, [nombre_usuario], (err, results) => {
      if (err) {
          return res.send('Error al obtener el usuario');
      }

      if (results.length === 0) {
          return res.send('Usuario no encontrado');
      }
      const user = results[0];
      // Verificar la contraseña
      const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
      if (!isPasswordValid) {
          return res.send('Contraseña incorrecta');
      }

      // Almacenar la información del usuario en la sesión
      req.session.user = {
          id: user.id,
          nombre_usuario: user.nombre_usuario,
          tipo_usuario: user.tipo_usuario // Aquí se establece el tipo de usuario en la sesión
      };

      // Redirigir al usuario a la página principal
      res.redirect('/');
  });
});

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.tipo_usuario });
});


// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Ruta para guardar datos de los empleados en la base de datos
app.post('/submit-data',requireLogin, requireRole(['RH']), (req, res) => {
    const { name, apellido, salario, departamento, fecha } = req.body;

    const query = 'INSERT INTO empleados (nombre, apellido, salario, departamento_id, fecha_contratacion) VALUES (?, ?, ?, ?, ?)';
    connection.query(query, [name, apellido, salario, departamento, fecha], (err, result) => {
        if (err) {
            console.error('Error al guardar en la base de datos:', err);
            return res.status(500).send('Error al guardar los datos en la base de datos.');
        }
        res.send(`Empleado ${name} guardado correctamente en la base de datos.`);
    });
});

// Ruta para mostrar empleados y departamentos en una tabla HTML USANDO JOIN
app.get('/empleados',requireLogin, requireRole(['Administrador','RH']), (req, res) => {
    const query = `
        SELECT empleados.id, empleados.nombre, empleados.apellido, departamentos.nombre AS departamento 
        FROM empleados
        JOIN departamentos ON empleados.departamento_id = departamentos.id;
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener empleados:', err);
            return res.status(500).send('Error al obtener los empleados de la base de datos.');
        }

        // Generar la tabla HTML con los resultados
        let html = `
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Empleados</title>
                <link rel="stylesheet" href="styles.css">
            </head>
            <body>
                <h1 style="text-align: center;">Lista de Empleados</h1>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Apellido</th>
                            <th>Departamento</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        results.forEach(row => {
            html += `
                <tr>
                    <td>${row.id}</td>
                    <td>${row.nombre}</td>
                    <td>${row.apellido}</td>
                    <td>${row.departamento}</td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
                <button onclick="window.location.href='/'">Volver</button>
            </body>
            </html>
        `;

        // Enviar la tabla HTML como respuesta
        res.send(html);
    });
});

// Ruta para eliminar un empleado solo por ID
app.post('/delete',requireLogin, requireRole(['RH']), (req, res) => {
    const { id } = req.body;  // Recibir el ID del empleado
    
    if (!id) {
        return res.status(400).send('El ID del empleado es obligatorio.');
    }

    const query = `
        DELETE FROM empleados
        WHERE id = ?
    `;

    connection.query(query, [id], (err, result) => {
        if (err) {
            console.error('Error al eliminar el empleado:', err);
            return res.status(500).send('Hubo un error al eliminar el empleado.');
        }

        if (result.affectedRows === 0) {
            return res.status(404).send('No se encontró un empleado con ese ID.');
        }

        res.send(`Empleado con ID ${id} eliminado correctamente.`);
    });
});

// Ruta para actualizar los datos de un empleado
app.post('/update-employee',requireLogin, requireRole(['RH']), (req, res) => {
    const { id, nombre, apellido, salario, departamento, fecha_contratacion } = req.body;

    if (!id || !nombre || !apellido || !salario || !departamento || !fecha_contratacion) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    // Consulta SQL para actualizar los datos del empleado
    const query = `
        UPDATE empleados
        SET nombre = ?, apellido = ?, salario = ?, departamento_id = ?, fecha_contratacion = ?
        WHERE id = ?
    `;

    connection.query(query, [nombre, apellido, salario, departamento, fecha_contratacion, id], (err, result) => {
        if (err) {
            console.error('Error al actualizar el empleado:', err);
            return res.status(500).send('Hubo un error al actualizar los datos del empleado.');
        }

        if (result.affectedRows === 0) {
            return res.status(404).send('No se encontró un empleado con ese ID.');
        }

        res.send(`Empleado con ID ${id} actualizado correctamente.`);
    });
});

// Ruta para obtener el salario promedio de los empleados
app.get('/promedio',requireLogin, requireRole(['Administrador']), (req, res) => {
    // Consulta SQL para calcular el salario promedio
    const query = 'SELECT AVG(salario) AS salario_promedio FROM empleados';

    connection.query(query, (err, result) => {
        if (err) {
            console.error('Error al obtener el salario promedio:', err);
            return res.status(500).send('Error al calcular el salario promedio.');
        }

        // Devolver el salario promedio al cliente
        const salarioPromedio = result[0].salario_promedio;
        res.send(`El salario promedio de los empleados es: ${salarioPromedio}`);
    });
});

// Ruta para contar los registros agrupados por departamento
app.get('/conteo',requireLogin, requireRole(['RH']), (req, res) => {
  const query = `
    SELECT departamentos.nombre AS departamento, COUNT(empleados.id) AS cantidad_empleados
    FROM empleados
    JOIN departamentos ON empleados.departamento_id = departamentos.id
    GROUP BY departamentos.nombre;
  `;

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al contar los registros:', err);
      return res.status(500).send('Error al contar los registros agrupados por departamento.');
    }

    // Generar la tabla HTML con los resultados
    let html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Conteo de Empleados por Departamento</title>
          <link rel="stylesheet" href="styles.css">
      </head>
      <body>
          <h1>Conteo de Empleados por Departamento</h1>
          <table border="1" cellpadding="10" cellspacing="0">
              <thead>
                  <tr>
                      <th>Departamento</th>
                      <th>Cantidad de Empleados</th>
                  </tr>
              </thead>
              <tbody>
    `;

    results.forEach(row => {
      html += `
        <tr>
            <td>${row.departamento}</td>
            <td>${row.cantidad_empleados}</td>
        </tr>
      `;
    });

    html += `
              </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver al Inicio</button>
      </body>
      </html>
    `;

    // Enviar la tabla HTML como respuesta
    res.send(html);
  });
});

 
// Ruta para obtener los datos de la vista de empleados y departamentos
app.get('/vista-empleados',requireLogin, requireRole(['RH']), (req, res) => {
    const query = 'SELECT * FROM vista_empleados_departamento';

    connection.query(query, (err, result) => {
        if (err) {
            console.error('Error al obtener los datos de la vista:', err);
            return res.status(500).send('Error al obtener los datos de la vista.');
        }

        // Crear la tabla HTML con los datos de la vista
        let html = `
            <h1>Lista de Empleados y Departamentos</h1>
            <link rel="stylesheet" href="styles.css">
            <table border="1" cellpadding="10" cellspacing="0">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Nombre</th>
                        <th>Apellido</th>
                        <th>Salario</th>
                        <th>Fecha de Contratación</th>
                        <th>Departamento</th>
                    </tr>
                </thead>
                <tbody>
        `;

        // Recorrer el resultado de la vista y agregar cada empleado en una fila de la tabla
        result.forEach(employee => {
            html += `
                <tr>
                    <td>${employee.id}</td>
                    <td>${employee.nombre}</td>
                    <td>${employee.apellido}</td>
                    <td>${employee.salario}</td>
                    <td>${employee.fecha_contratacion}</td>
                    <td>${employee.departamento}</td>
                </tr>
            `;
        });

        // Cerrar las etiquetas de la tabla
        html += `</tbody></table>`;

        // Enviar el HTML como respuesta
        res.send(html);
    });
});

// Ruta para mostrar todos los usuarios en una tabla HTML
app.get('/usuarios',requireLogin, requireRole(['Administrador']), (req, res) => {
  const query = `
    SELECT id, nombre_usuario, tipo_usuario 
    FROM usuarios
  `;

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los usuarios:', err);
      return res.status(500).send('Error al obtener los usuarios de la base de datos.');
    }

    // Generar el HTML para la tabla
    let html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Lista de Usuarios</title>
          <link rel="stylesheet" href="styles.css">
      </head>
      <body>
          <h1 style="text-align: center;">Lista de Usuarios</h1>
          <table>
              <thead>
                  <tr>
                      <th>ID</th>
                      <th>Nombre de Usuario</th>
                      <th>Tipo de Usuario</th>
                  </tr>
              </thead>
              <tbody>
    `;

    results.forEach((user) => {
      html += `
        <tr>
          <td>${user.id}</td>
          <td>${user.nombre_usuario}</td>
          <td>${user.tipo_usuario}</td>
        </tr>
      `;
    });

    html += `
              </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver al Inicio</button>
      </body>
      </html>
    `;

    // Enviar la tabla HTML como respuesta
    res.send(html);
  });
});

// Ruta para obtener empleados con salario superior al promedio de su departamento
app.get('/empleados-salario-superior',requireLogin, requireRole(['RH']), (req, res) => {
  const query = `
    SELECT e.id, e.nombre, e.apellido, e.salario, d.nombre AS departamento
    FROM empleados e
    JOIN departamentos d ON e.departamento_id = d.id
    WHERE e.salario > (
      SELECT AVG(salario)
      FROM empleados
      WHERE departamento_id = e.departamento_id
    )
  `;

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los empleados:', err);
      return res.status(500).send('Error al obtener los empleados con salario superior al promedio.');
    }

    // Generar la tabla HTML con los resultados
    let html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Empleados con Salario Superior al Promedio</title>
          <link rel="stylesheet" href="styles.css">
      </head>
      <body>
          <h1 style="text-align: center;">Empleados con Salario Superior al Promedio por Departamento</h1>
          <table>
              <thead>
                  <tr>
                      <th>ID</th>
                      <th>Nombre</th>
                      <th>Apellido</th>
                      <th>Salario</th>
                      <th>Departamento</th>
                  </tr>
              </thead>
              <tbody>
    `;

    results.forEach(row => {
      html += `
        <tr>
            <td>${row.id}</td>
            <td>${row.nombre}</td>
            <td>${row.apellido}</td>
            <td>${row.salario}</td>
            <td>${row.departamento}</td>
        </tr>
      `;
    });

    html += `
              </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    // Enviar la tabla HTML como respuesta
    res.send(html);
  });
});


//Ruta de Búsqueda en el Servidor
app.get('/buscar',requireLogin, requireRole(['Administrador']), (req, res) => {
  const query = req.query.query;
  const sql = `SELECT nombre, apellido FROM empleados WHERE nombre LIKE ?`;
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

//Ruta para manejar la carga
const upload = multer({ dest: 'uploads/' });

app.post('/upload',requireLogin, requireRole(['Administrador']), upload.single('excelFile'), (req, res) => {
  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  data.forEach(row => {
    const { nombre, descripcion } = row;
    const sql = `INSERT INTO equipo_medico (nombre, cantidad) VALUES (?, ?)`;
    connection.query(sql, [nombre, descripcion], err => {
      if (err) throw err;
    });
  });

  res.send('<h1>Archivo cargado y datos guardados</h1><a href="/equipos.html">Volver</a>');
});

// Ruta para insertar los datos en la tabla Equipo_Medico
app.post('/insertar-equipo',requireLogin, requireRole(['Ingeniero']), (req, res) => {
  const { nombre, cantidad } = req.body;

  // Validar los datos
  if (!nombre || !cantidad) {
    return res.status(400).send('Todos los campos son obligatorios.');
  }

  const query = 'INSERT INTO Equipo_Medico (nombre, cantidad) VALUES (?, ?)';
  connection.query(query, [nombre, cantidad], (err, result) => {
    if (err) {
      console.error('Error al insertar equipo médico:', err);
      return res.status(500).send('Error al insertar equipo médico en la base de datos.');
    }
    res.send(`
       <link rel="stylesheet" href="styles.css">
      <h1>Equipo Médico Agregado Correctamente</h1>
      <p>Nombre: ${nombre}</p>
      <p>Cantidad: ${cantidad}</p>
      <button onclick="window.location.href='/'" style="display: block; margin: 20px auto;">Volver al Inicio</button>
    `);
  });
});

//Ruta para manejar la descarga
app.get('/download',requireLogin, requireRole(['Administrador']), (req, res) => {
  const sql = `SELECT * FROM Equipo_Medico`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Equipos');

    const filePath = path.join(__dirname, 'uploads', 'equipos.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'equipos.xlsx');
  });
});

// Ruta para ver todos los datos de la tabla Equipo_Medico
app.get('/ver-equipo',requireLogin, requireRole(['Ingeniero']), (req, res) => {
  const query = 'SELECT * FROM Equipo_Medico';

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los datos del equipo médico:', err);
      return res.status(500).send('Error al obtener los datos del equipo médico.');
    }

    // Generar la tabla HTML con los resultados
    let html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Lista de Equipo Médico</title>
          <link rel="stylesheet" href="styles.css">
      </head>
      <body>
          <h1>Lista de Equipo Médico</h1>
          <table border="1" cellpadding="10" cellspacing="0">
              <thead>
                  <tr>
                      <th>ID</th>
                      <th>Nombre</th>
                      <th>Cantidad</th>
                  </tr>
              </thead>
              <tbody>
    `;

    results.forEach(row => {
      html += `
        <tr>
            <td>${row.id}</td>
            <td>${row.nombre}</td>
            <td>${row.cantidad}</td>
        </tr>
      `;
    });

    html += `
              </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver al Inicio</button>
      </body>
      </html>
    `;

    // Enviar la tabla HTML como respuesta
    res.send(html);
  });
});

// Ruta para eliminar un usuario por su ID
app.post('/eliminar-usuario',requireLogin, requireRole(['Administrador']), (req, res) => {
  const { id } = req.body; // Obtener el ID del usuario desde el cuerpo de la solicitud

  if (!id) {
    return res.status(400).send('El ID del usuario es obligatorio.');
  }

  // Consulta SQL para eliminar el usuario
  const query = 'DELETE FROM usuarios WHERE id = ?';

  connection.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error al eliminar el usuario:', err);
      return res.status(500).send('Hubo un error al eliminar el usuario.');
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('No se encontró un usuario con ese ID.');
    }

    res.send(`Usuario con ID ${id} eliminado correctamente.`);
  });
});

// Ruta para eliminar un equipo médico por su ID
app.post('/eliminar-equipo',requireLogin, requireRole(['Ingeniero']), (req, res) => {
  const { id } = req.body;  // Obtener el ID del equipo médico desde el cuerpo de la solicitud

  if (!id) {
    return res.status(400).send('El ID del equipo médico es obligatorio.');
  }

  // Consulta SQL para eliminar el equipo médico
  const query = 'DELETE FROM Equipo_Medico WHERE id = ?';

  connection.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error al eliminar el equipo médico:', err);
      return res.status(500).send('Hubo un error al eliminar el equipo médico.');
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('No se encontró un equipo médico con ese ID.');
    }

    res.send(`Equipo médico con ID ${id} eliminado correctamente.`);
  });
});


// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));
