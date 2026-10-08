// 1. Importar dependencias
require('dotenv').config();
const crypto = require('crypto');
const { promisify } = require('util');
const express = require('express');
const mongoose = require('mongoose');

//IMPORTACIÓN DE MODELOS
const Mascota = require('./modelos/Mascota');
const Usuario = require('./modelos/Usuario');
const SolicitudAdopcion = require('./modelos/SolicitudAdopcion');
const ReporteEmergencia = require('./modelos/ReporteEmergencia');

const app = express();
// El frontend usa el 3000, por eso la API corre en otro puerto (4000 por defecto)
const puerto = process.env.PORT || 4000;

// Límite de 2 MB: las fotos de las mascotas llegan reducidas (unos 100-300 KB)
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Conexión a la Base de Datos MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log('¡Conexión exitosa a la base de datos MongoDB Atlas!');
        await crearAdminInicial();
    })
    .catch(err => console.error('Error crítico al conectar con MongoDB:', err));

// ==========================================
//        SEGURIDAD (contraseñas y sesión)
// ==========================================

const scrypt = promisify(crypto.scrypt);

// Contraseñas: se guardan con hash (scrypt + sal aleatoria), nunca en texto plano
async function hashPassword(password) {
    const sal = crypto.randomBytes(16);
    const hash = await scrypt(password, sal, 64);
    return `${sal.toString('hex')}:${hash.toString('hex')}`;
}

async function verificarPassword(password, guardado) {
    const [salHex, hashHex] = String(guardado || '').split(':');
    if (!salHex || !hashHex) return false; // formato inválido (por ejemplo, una clave antigua en texto plano)
    const esperado = Buffer.from(hashHex, 'hex');
    const calculado = await scrypt(password, Buffer.from(salHex, 'hex'), esperado.length);
    return crypto.timingSafeEqual(calculado, esperado);
}

// Token de sesión (formato JWT, firmado con HS256)
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('AVISO: falta JWT_SECRET en el .env. Se usa una clave temporal y las sesiones se cerrarán al reiniciar la API.');
}

const codificar = (objeto) => Buffer.from(JSON.stringify(objeto)).toString('base64url');
const firmar = (contenido) => crypto.createHmac('sha256', JWT_SECRET).update(contenido).digest();

function crearToken(payload, horas = 8) {
    const encabezado = codificar({ alg: 'HS256', typ: 'JWT' });
    const cuerpo = codificar({ ...payload, exp: Math.floor(Date.now() / 1000) + horas * 3600 });
    const firma = firmar(`${encabezado}.${cuerpo}`).toString('base64url');
    return `${encabezado}.${cuerpo}.${firma}`;
}

function verificarToken(token) {
    if (typeof token !== 'string') return null;
    const partes = token.split('.');
    if (partes.length !== 3) return null;
    const [encabezado, cuerpo, firma] = partes;
    const recibida = Buffer.from(firma, 'base64url');
    const esperada = firmar(`${encabezado}.${cuerpo}`);
    if (recibida.length !== esperada.length || !crypto.timingSafeEqual(recibida, esperada)) return null;
    try {
        const datos = JSON.parse(Buffer.from(cuerpo, 'base64url').toString());
        if (JSON.parse(Buffer.from(encabezado, 'base64url').toString()).alg !== 'HS256') return null;
        if (!datos.exp || datos.exp < Math.floor(Date.now() / 1000)) return null;
        return datos;
    } catch {
        return null;
    }
}

// Middleware: exige haber iniciado sesión (header "Authorization: Bearer <token>")
async function autenticar(req, res, next) {
    const [tipo, token] = (req.headers.authorization || '').split(' ');
    const datos = tipo === 'Bearer' ? verificarToken(token) : null;
    if (!datos) {
        return res.status(401).json({ error: 'Debes iniciar sesión para realizar esta acción.' });
    }
    try {
        // Se consulta el usuario en cada petición para respetar cambios de rol, aprobaciones o suspensiones
        const usuario = await Usuario.findById(datos.id).select('nombre email rol estado_aprobacion');
        if (!usuario || ['Suspendido', 'Rechazado'].includes(usuario.estado_aprobacion)) {
            return res.status(401).json({ error: 'Tu sesión no es válida o tu cuenta no está activa.' });
        }
        if (usuario.rol === 'Refugio' && usuario.estado_aprobacion !== 'Aprobado') {
            return res.status(403).json({ error: 'Tu refugio aún está pendiente de aprobación por el administrador.' });
        }
        req.usuario = {
            id: usuario._id.toString(),
            nombre: usuario.nombre,
            email: usuario.email,
            rol: usuario.rol,
            estado: usuario.estado_aprobacion
        };
        next();
    } catch (error) {
        console.error('Error al validar la sesión:', error);
        res.status(500).json({ error: 'Error interno al validar la sesión.' });
    }
}

// Middleware: limita la ruta a ciertos roles
function soloRoles(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.usuario.rol)) {
            return res.status(403).json({ error: 'No tienes permisos para realizar esta acción.' });
        }
        if (req.usuario.rol === 'Refugio' && req.usuario.estado !== 'Aprobado') {
            return res.status(403).json({ error: 'Tu refugio aún está pendiente de aprobación por el administrador.' });
        }
        next();
    };
}

// ==========================================
//        UTILIDADES
// ==========================================

// Copia solo los campos permitidos del body (evita que envíen campos como "rol" o "estado_aprobacion")
function permitir(origen, campos) {
    const resultado = {};
    for (const campo of campos) {
        if (origen && origen[campo] !== undefined) resultado[campo] = origen[campo];
    }
    return resultado;
}

// Respuestas de error más precisas que un 500 para todo
function responderError(res, error, mensajeGenerico) {
    if (error.name === 'ValidationError') {
        const detalle = Object.values(error.errors).map(e => e.message).join(' ');
        return res.status(400).json({ error: `Datos inválidos: ${detalle}` });
    }
    if (error.code === 11000) {
        const mensaje = error.keyPattern && error.keyPattern.email
            ? 'Este correo ya está registrado.'
            : 'Ya existe un registro con ese valor.';
        return res.status(409).json({ error: mensaje });
    }
    if (error.name === 'CastError') {
        return res.status(400).json({ error: 'Alguno de los datos enviados tiene un formato inválido.' });
    }
    console.error(mensajeGenerico, error);
    res.status(500).json({ error: mensajeGenerico });
}

function passwordValida(password) {
    return typeof password === 'string' && password.length >= 8;
}

// Valida que cualquier :id de la URL sea un ObjectId de MongoDB
app.param('id', (req, res, next, id) => {
    if (!mongoose.isValidObjectId(id)) {
        return res.status(400).json({ error: 'El identificador enviado no es válido.' });
    }
    next();
});

// Crea el primer administrador si en el .env se definen ADMIN_EMAIL y ADMIN_PASSWORD
async function crearAdminInicial() {
    const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) return;
    try {
        const email = ADMIN_EMAIL.trim().toLowerCase();
        if (await Usuario.findOne({ email })) return;
        await Usuario.create({
            nombre: 'Administrador',
            email,
            password: await hashPassword(ADMIN_PASSWORD),
            rol: 'Admin',
            estado_aprobacion: 'Aprobado'
        });
        console.log(`Administrador inicial creado: ${email}`);
    } catch (error) {
        console.error('No se pudo crear el administrador inicial:', error);
    }
}

// ==========================================
//        RUTAS DE LA API
// ==========================================

// Ruta de prueba principal
app.get('/', (req, res) => {
    res.json({ mensaje: 'API de Bienestar Animal Bogotá funcionando correctamente.' });
});

// Inicio de sesión
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body || {};
        // Solo texto: evita inyecciones del tipo { "email": { "$gt": "" } }
        if (typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
        }

        const usuario = await Usuario.findOne({ email: email.trim().toLowerCase() }).select('+password');
        // Mismo mensaje y mismo trabajo si el correo no existe, para no revelar qué correos están registrados
        const claveCorrecta = await verificarPassword(password, usuario ? usuario.password : '');
        if (!usuario || !claveCorrecta) {
            return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
        }
        if (usuario.estado_aprobacion === 'Pendiente') {
            return res.status(403).json({ error: 'Tu registro está pendiente de aprobación por el administrador. Podrás ingresar cuando sea aprobado.' });
        }
        if (usuario.estado_aprobacion === 'Rechazado') {
            return res.status(403).json({ error: 'Tu solicitud de registro fue rechazada por el administrador.' });
        }
        if (usuario.estado_aprobacion === 'Suspendido') {
            return res.status(403).json({ error: 'Tu cuenta está suspendida. Comunícate con el administrador.' });
        }

        res.status(200).json({
            mensaje: 'Inicio de sesión exitoso',
            token: crearToken({ id: usuario._id.toString(), rol: usuario.rol }),
            usuario: {
                id: usuario._id,
                nombre: usuario.nombre,
                email: usuario.email,
                rol: usuario.rol,
                estado_aprobacion: usuario.estado_aprobacion
            }
        });
    } catch (error) {
        responderError(res, error, 'Error interno al iniciar sesión.');
    }
});

// Datos de la sesión actual (el frontend lo usa para saber quién es y qué rol tiene)
app.get('/api/yo', autenticar, (req, res) => {
    res.status(200).json({ usuario: req.usuario });
});

// ==========================================
//        MASCOTAS
// ==========================================
const CAMPOS_MASCOTA = ['nombre', 'especie', 'raza', 'edad', 'sexo', 'tamaño', 'descripcion', 'imagen', 'estado'];
const ESTADOS_MASCOTA = ['Disponible', 'En proceso', 'Adoptado'];

// La imagen puede ser una foto subida (data URL reducida), una ruta de /imagenes o un enlace http(s)
const IMAGEN_SUBIDA = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
function imagenValida(imagen) {
    if (typeof imagen !== 'string') return false;
    if (imagen.startsWith('data:')) return imagen.length <= 700000 && IMAGEN_SUBIDA.test(imagen);
    return /^\/imagenes\/[\w.-]+$/.test(imagen) || /^https?:\/\/\S+$/.test(imagen);
}

// Prepara una mascota para enviarla: las fotos subidas se sirven por su propia ruta
// (así las listas no cargan cientos de KB por cada animal)
function publicarMascota(mascota) {
    const obj = typeof mascota.toJSON === 'function' ? mascota.toJSON() : { ...mascota };
    if (typeof obj.imagen === 'string' && obj.imagen.startsWith('data:')) {
        obj.imagen = `/api/mascotas/${obj._id}/imagen`;
    }
    if (obj.refugio_id && obj.refugio_id.nombre) {
        obj.refugio_nombre = obj.refugio_id.nombre;
        obj.refugio_id = obj.refugio_id._id;
    }
    delete obj.__v;
    return obj;
}

// Un refugio solo gestiona sus propias mascotas; el administrador puede moderar todas
function puedeGestionarMascota(mascota, usuario) {
    return usuario.rol === 'Admin' ||
        (mascota.refugio_id && mascota.refugio_id.toString() === usuario.id);
}

// Solo los refugios aprobados registran mascotas
app.post('/api/mascotas', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const datos = permitir(req.body, CAMPOS_MASCOTA);
        if (datos.imagen === '') delete datos.imagen;
        if (datos.imagen !== undefined && !imagenValida(datos.imagen)) {
            return res.status(400).json({ error: 'La imagen no es válida o es demasiado grande.' });
        }
        datos.refugio_id = req.usuario.id;

        const nuevaMascota = new Mascota(datos);
        await nuevaMascota.save();
        res.status(201).json({
            mensaje: 'Mascota registrada exitosamente',
            mascota: publicarMascota(nuevaMascota)
        });
    } catch (error) {
        responderError(res, error, 'Error al registrar la mascota en la base de datos');
    }
});

// El catálogo es público: cualquier visitante puede ver las mascotas (filtro opcional ?estado=Disponible)
app.get('/api/mascotas', async (req, res) => {
    try {
        const filtro = {};
        if (req.query.estado !== undefined) {
            if (!ESTADOS_MASCOTA.includes(req.query.estado)) {
                return res.status(400).json({ error: 'Estado de mascota no válido.' });
            }
            filtro.estado = req.query.estado;
        }
        const listaMascotas = await Mascota.find(filtro).sort({ createdAt: -1 }).populate('refugio_id', 'nombre');

        res.status(200).json({
            cantidad: listaMascotas.length,
            mascotas: listaMascotas.map(publicarMascota)
        });
    } catch (error) {
        responderError(res, error, 'Hubo un problema al obtener el catálogo de mascotas.');
    }
});

// Mascotas del refugio que inició sesión (esta ruta va antes que /api/mascotas/:id)
app.get('/api/mascotas/mias', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const lista = await Mascota.find({ refugio_id: req.usuario.id }).sort({ createdAt: -1 });
        res.status(200).json({ cantidad: lista.length, mascotas: lista.map(publicarMascota) });
    } catch (error) {
        responderError(res, error, 'No se pudieron obtener las mascotas del refugio.');
    }
});

app.get('/api/mascotas/:id', async (req, res) => {
    try {
        const mascota = await Mascota.findById(req.params.id).populate('refugio_id', 'nombre');
        if (!mascota) {
            return res.status(404).json({ error: 'Mascota no encontrada en el sistema' });
        }
        res.status(200).json({ mascota: publicarMascota(mascota) });
    } catch (error) {
        responderError(res, error, 'Error al consultar la mascota.');
    }
});

// Sirve la foto cuando fue subida desde el panel del refugio
app.get('/api/mascotas/:id/imagen', async (req, res) => {
    try {
        const mascota = await Mascota.findById(req.params.id).select('imagen');
        const imagen = mascota && mascota.imagen;
        if (typeof imagen !== 'string' || !imagen.startsWith('data:')) {
            return res.status(404).json({ error: 'La mascota no tiene una imagen cargada.' });
        }
        res.set('Content-Type', imagen.slice(5, imagen.indexOf(';')));
        res.set('Cache-Control', 'public, max-age=300');
        res.send(Buffer.from(imagen.slice(imagen.indexOf(',') + 1), 'base64'));
    } catch (error) {
        responderError(res, error, 'Error al obtener la imagen.');
    }
});

app.put('/api/mascotas/:id', autenticar, soloRoles('Refugio', 'Admin'), async (req, res) => {
    try {
        const mascota = await Mascota.findById(req.params.id);
        if (!mascota) {
            return res.status(404).json({ error: 'Mascota no encontrada en el sistema' });
        }
        if (!puedeGestionarMascota(mascota, req.usuario)) {
            return res.status(403).json({ error: 'Solo puedes modificar las mascotas de tu refugio.' });
        }

        const cambios = permitir(req.body, CAMPOS_MASCOTA);
        if (cambios.imagen !== undefined && !imagenValida(cambios.imagen)) {
            return res.status(400).json({ error: 'La imagen no es válida o es demasiado grande.' });
        }
        mascota.set(cambios);
        await mascota.save();

        res.status(200).json({
            mensaje: 'Estado del animal actualizado exitosamente',
            mascota: publicarMascota(mascota)
        });
    } catch (error) {
        responderError(res, error, 'Error interno al modificar el registro de la mascota.');
    }
});

app.delete('/api/mascotas/:id', autenticar, soloRoles('Refugio', 'Admin'), async (req, res) => {
    try {
        const mascota = await Mascota.findById(req.params.id);
        if (!mascota) {
            return res.status(404).json({ error: 'La mascota no existe o ya fue eliminada' });
        }
        if (!puedeGestionarMascota(mascota, req.usuario)) {
            return res.status(403).json({ error: 'Solo puedes eliminar las mascotas de tu refugio.' });
        }

        await mascota.deleteOne();

        res.status(200).json({
            mensaje: 'Mascota eliminada del sistema correctamente',
            mascota_borrada: publicarMascota(mascota)
        });
    } catch (error) {
        responderError(res, error, 'Error interno al intentar borrar el registro.');
    }
});

// ==========================================
//        SOLICITUDES DE ADOPCIÓN
// ==========================================

// El ciudadano solicita adoptar una mascota disponible; le llega al refugio que la tiene
app.post('/api/solicitudes', autenticar, soloRoles('Ciudadano'), async (req, res) => {
    try {
        const { mascota_id, mensaje } = req.body || {};
        if (typeof mascota_id !== 'string' || !mongoose.isValidObjectId(mascota_id)) {
            return res.status(400).json({ error: 'La mascota indicada no es válida.' });
        }
        if (typeof mensaje !== 'string' || mensaje.trim().length < 10) {
            return res.status(400).json({ error: 'Cuéntale al refugio por qué quieres adoptar (mínimo 10 caracteres).' });
        }

        const mascota = await Mascota.findById(mascota_id);
        if (!mascota) {
            return res.status(404).json({ error: 'Mascota no encontrada en el sistema' });
        }
        if (mascota.estado !== 'Disponible') {
            return res.status(409).json({ error: 'Esta mascota ya no está disponible para adopción.' });
        }
        if (!mascota.refugio_id) {
            return res.status(400).json({ error: 'Esta mascota no tiene un refugio asignado.' });
        }

        const existente = await SolicitudAdopcion.findOne({
            mascota_id,
            ciudadano_id: req.usuario.id,
            estado: 'Pendiente'
        });
        if (existente) {
            return res.status(409).json({ error: 'Ya tienes una solicitud pendiente para esta mascota.' });
        }

        const solicitud = await SolicitudAdopcion.create({
            mascota_id,
            ciudadano_id: req.usuario.id,
            refugio_id: mascota.refugio_id,
            mensaje: mensaje.trim()
        });
        res.status(201).json({
            mensaje: 'Solicitud enviada. El refugio revisará tu solicitud y te responderá pronto.',
            solicitud
        });
    } catch (error) {
        responderError(res, error, 'Error al registrar la solicitud de adopción.');
    }
});

// Solicitudes que envió el ciudadano
app.get('/api/solicitudes/mias', autenticar, soloRoles('Ciudadano'), async (req, res) => {
    try {
        const lista = await SolicitudAdopcion.find({ ciudadano_id: req.usuario.id })
            .sort({ createdAt: -1 })
            .populate('mascota_id', 'nombre especie')
            .populate('refugio_id', 'nombre');
        res.status(200).json({ cantidad: lista.length, solicitudes: lista });
    } catch (error) {
        responderError(res, error, 'No se pudieron obtener tus solicitudes.');
    }
});

// Solicitudes que recibió el refugio por sus mascotas
app.get('/api/solicitudes/recibidas', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const lista = await SolicitudAdopcion.find({ refugio_id: req.usuario.id })
            .sort({ createdAt: -1 })
            .populate('mascota_id', 'nombre especie')
            .populate('ciudadano_id', 'nombre email telefono');
        res.status(200).json({ cantidad: lista.length, solicitudes: lista });
    } catch (error) {
        responderError(res, error, 'No se pudieron obtener las solicitudes recibidas.');
    }
});

// El refugio acepta o rechaza la solicitud ("Aprobada" o "Rechazada")
app.put('/api/solicitudes/:id/responder', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const { decision, respuesta } = req.body || {};
        if (!['Aprobada', 'Rechazada'].includes(decision)) {
            return res.status(400).json({ error: 'La decisión debe ser "Aprobada" o "Rechazada".' });
        }

        // Solo la puede responder el refugio dueño de la mascota
        const solicitud = await SolicitudAdopcion.findOne({ _id: req.params.id, refugio_id: req.usuario.id });
        if (!solicitud) {
            return res.status(404).json({ error: 'Solicitud no encontrada.' });
        }
        if (solicitud.estado !== 'Pendiente') {
            return res.status(409).json({ error: 'Esta solicitud ya fue respondida.' });
        }

        solicitud.estado = decision;
        if (typeof respuesta === 'string' && respuesta.trim()) {
            solicitud.respuesta = respuesta.trim().slice(0, 500);
        }
        await solicitud.save();

        if (decision === 'Aprobada') {
            // La mascota queda adoptada y las demás solicitudes pendientes por ella se cierran
            await Mascota.findByIdAndUpdate(solicitud.mascota_id, { estado: 'Adoptado' });
            await SolicitudAdopcion.updateMany(
                { mascota_id: solicitud.mascota_id, estado: 'Pendiente', _id: { $ne: solicitud._id } },
                { estado: 'Rechazada', respuesta: 'La mascota ya fue adoptada por otra persona.' }
            );
        }

        res.status(200).json({ mensaje: `Solicitud ${decision.toLowerCase()}`, solicitud });
    } catch (error) {
        responderError(res, error, 'Error al responder la solicitud.');
    }
});

// ==========================================
//        REPORTES DE EMERGENCIA
// ==========================================

// El ciudadano envía el reporte; lo ven todos los refugios aprobados
app.post('/api/emergencias', autenticar, soloRoles('Ciudadano'), async (req, res) => {
    try {
        const datos = permitir(req.body, ['tipo', 'ubicacion', 'descripcion']);
        for (const campo of ['tipo', 'ubicacion', 'descripcion']) {
            if (typeof datos[campo] !== 'string') {
                return res.status(400).json({ error: 'Completa el tipo, la ubicación y la descripción de la emergencia.' });
            }
        }
        const reporte = await ReporteEmergencia.create({ ...datos, ciudadano_id: req.usuario.id });
        res.status(201).json({
            mensaje: 'Alerta enviada a los refugios. Te avisaremos cuando uno acepte atender el caso.',
            reporte
        });
    } catch (error) {
        responderError(res, error, 'Error al registrar el reporte de emergencia.');
    }
});

// Reportes que envió el ciudadano
app.get('/api/emergencias/mias', autenticar, soloRoles('Ciudadano'), async (req, res) => {
    try {
        const lista = await ReporteEmergencia.find({ ciudadano_id: req.usuario.id })
            .sort({ createdAt: -1 })
            .populate('atendido_por', 'nombre telefono');
        res.status(200).json({ cantidad: lista.length, emergencias: lista });
    } catch (error) {
        responderError(res, error, 'No se pudieron obtener tus reportes.');
    }
});

// Reportes que ve el refugio: los pendientes que no ha rechazado y los que él aceptó
app.get('/api/emergencias/recibidas', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const lista = await ReporteEmergencia.find({
            $or: [
                { estado: 'Pendiente', rechazado_por: { $ne: req.usuario.id } },
                { atendido_por: req.usuario.id }
            ]
        })
            .sort({ createdAt: -1 })
            .populate('ciudadano_id', 'nombre email telefono');
        res.status(200).json({ cantidad: lista.length, emergencias: lista });
    } catch (error) {
        responderError(res, error, 'No se pudieron obtener los reportes de emergencia.');
    }
});

// El refugio acepta ("Aceptada") o rechaza ("Rechazada") atender el reporte
app.put('/api/emergencias/:id/responder', autenticar, soloRoles('Refugio'), async (req, res) => {
    try {
        const { decision } = req.body || {};
        if (!['Aceptada', 'Rechazada'].includes(decision)) {
            return res.status(400).json({ error: 'La decisión debe ser "Aceptada" o "Rechazada".' });
        }

        // La condición estado: 'Pendiente' evita que dos refugios acepten el mismo reporte a la vez
        const cambio = decision === 'Aceptada'
            ? { estado: 'Aceptada', atendido_por: req.usuario.id }
            : { $addToSet: { rechazado_por: req.usuario.id } };
        const reporte = await ReporteEmergencia.findOneAndUpdate(
            { _id: req.params.id, estado: 'Pendiente' },
            cambio,
            { new: true }
        );
        if (!reporte) {
            return res.status(409).json({ error: 'Este reporte ya fue tomado por otro refugio o ya no está disponible.' });
        }

        res.status(200).json({
            mensaje: decision === 'Aceptada' ? 'Aceptaste atender el reporte.' : 'Rechazaste el reporte.',
            reporte
        });
    } catch (error) {
        responderError(res, error, 'Error al responder el reporte de emergencia.');
    }
});

// ==========================================
//        ADMINISTRADOR: APROBACIÓN DE REFUGIOS
// ==========================================

// Lista de refugios (filtro opcional ?estado=Pendiente)
app.get('/api/refugios', autenticar, soloRoles('Admin'), async (req, res) => {
    try {
        const filtro = { rol: 'Refugio' };
        if (req.query.estado !== undefined) {
            if (!['Pendiente', 'Aprobado', 'Rechazado', 'Suspendido'].includes(req.query.estado)) {
                return res.status(400).json({ error: 'Estado no válido.' });
            }
            filtro.estado_aprobacion = req.query.estado;
        }
        const lista = await Usuario.find(filtro).sort({ createdAt: -1 });
        res.status(200).json({ cantidad: lista.length, refugios: lista });
    } catch (error) {
        responderError(res, error, 'No se pudo obtener la lista de refugios.');
    }
});

// El administrador aprueba o rechaza el registro de un refugio
app.put('/api/refugios/:id/estado', autenticar, soloRoles('Admin'), async (req, res) => {
    try {
        const { estado } = req.body || {};
        if (!['Aprobado', 'Rechazado', 'Suspendido'].includes(estado)) {
            return res.status(400).json({ error: 'El estado debe ser "Aprobado", "Rechazado" o "Suspendido".' });
        }
        const refugio = await Usuario.findOneAndUpdate(
            { _id: req.params.id, rol: 'Refugio' },
            { estado_aprobacion: estado },
            { new: true, runValidators: true }
        );
        if (!refugio) {
            return res.status(404).json({ error: 'Refugio no encontrado.' });
        }
        res.status(200).json({ mensaje: `Refugio ${estado.toLowerCase()}`, refugio });
    } catch (error) {
        responderError(res, error, 'Error al actualizar el estado del refugio.');
    }
});

// Cifras reales para el panel del administrador
app.get('/api/admin/resumen', autenticar, soloRoles('Admin'), async (req, res) => {
    try {
        const [animales, refugios, pendientes, usuarios, adopciones] = await Promise.all([
            Mascota.countDocuments({ estado: 'Disponible' }),
            Usuario.countDocuments({ rol: 'Refugio', estado_aprobacion: 'Aprobado' }),
            Usuario.countDocuments({ rol: 'Refugio', estado_aprobacion: 'Pendiente' }),
            Usuario.countDocuments({}),
            SolicitudAdopcion.countDocuments({ estado: 'Aprobada' })
        ]);
        res.status(200).json({ animales, refugios, pendientes, usuarios, adopciones });
    } catch (error) {
        responderError(res, error, 'No se pudo calcular el resumen.');
    }
});


// CRUD de Usuarios
const CAMPOS_PERFIL = ['nombre', 'email', 'telefono', 'direccion', 'password'];
const ROLES_PUBLICOS = ['Ciudadano', 'Refugio']; // "Admin" nunca se puede elegir al registrarse

// Registro público
app.post('/api/usuarios', async (req, res) => {
    try {
        const datos = permitir(req.body, CAMPOS_PERFIL);
        const rol = req.body.rol === undefined ? 'Ciudadano' : req.body.rol;

        if (!ROLES_PUBLICOS.includes(rol)) {
            return res.status(400).json({ error: 'Tipo de cuenta no permitido.' });
        }
        if (!passwordValida(datos.password)) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
        }

        datos.password = await hashPassword(datos.password);
        datos.rol = rol;
        // Los refugios deben ser aprobados por el administrador antes de operar
        datos.estado_aprobacion = rol === 'Refugio' ? 'Pendiente' : 'Aprobado';

        const nuevoUsuario = new Usuario(datos);
        await nuevoUsuario.save();
        res.status(201).json({
            mensaje: rol === 'Refugio'
                ? 'Registro exitoso. Tu refugio quedará activo cuando el administrador lo apruebe.'
                : 'Usuario registrado exitosamente',
            usuario: nuevoUsuario // el modelo oculta la contraseña al convertirse a JSON
        });
    } catch (error) {
        responderError(res, error, 'Error al registrar el usuario en la base de datos');
    }
});

// Solo el administrador puede ver el directorio de usuarios
app.get('/api/usuarios', autenticar, soloRoles('Admin'), async (req, res) => {
    try {
        const listaUsuarios = await Usuario.find();

        res.status(200).json({
            cantidad: listaUsuarios.length,
            usuarios: listaUsuarios
        });
    } catch (error) {
        responderError(res, error, 'Hubo un problema al obtener el directorio de usuarios.');
    }
});

// Cada usuario edita su propio perfil; el administrador puede editar cualquiera (incluido rol y aprobación)
app.put('/api/usuarios/:id', autenticar, async (req, res) => {
    try {
        const esAdmin = req.usuario.rol === 'Admin';
        if (!esAdmin && req.usuario.id !== req.params.id) {
            return res.status(403).json({ error: 'Solo puedes modificar tu propio perfil.' });
        }

        const campos = esAdmin ? [...CAMPOS_PERFIL, 'rol', 'estado_aprobacion'] : CAMPOS_PERFIL;
        const nuevosDatos = permitir(req.body, campos);

        if (nuevosDatos.password !== undefined) {
            if (!passwordValida(nuevosDatos.password)) {
                return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
            }
            nuevosDatos.password = await hashPassword(nuevosDatos.password);
        }

        const usuarioActualizado = await Usuario.findByIdAndUpdate(req.params.id, nuevosDatos, { new: true, runValidators: true });

        if (!usuarioActualizado) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.status(200).json({
            mensaje: 'Perfil actualizado exitosamente',
            usuario: usuarioActualizado
        });
    } catch (error) {
        responderError(res, error, 'Error interno al modificar el usuario.');
    }
});

app.delete('/api/usuarios/:id', autenticar, soloRoles('Admin'), async (req, res) => {
    try {
        const usuarioEliminado = await Usuario.findByIdAndDelete(req.params.id);

        if (!usuarioEliminado) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.status(200).json({
            mensaje: 'Usuario eliminado exitosamente del directorio'
        });
    } catch (error) {
        responderError(res, error, 'Error interno al intentar borrar el usuario.');
    }
});

// Errores generales: cuerpo demasiado grande o JSON mal formado
app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'Los datos enviados son demasiado grandes (por ejemplo, la foto).' });
    }
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'El formato de los datos enviados no es válido.' });
    }
    console.error('Error no controlado:', err);
    res.status(500).json({ error: 'Error interno del servidor.' });
});

//Inicio del servidor (solo si se ejecuta directamente con "node server.js")
if (require.main === module) {
    app.listen(puerto, () => {
        console.log(`¡Servidor API Backend corriendo en http://localhost:${puerto}!`);
    });
}

module.exports = app;
