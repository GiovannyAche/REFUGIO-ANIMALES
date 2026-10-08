const express = require('express');
const path = require('path');

const app = express();
const puerto = 3000;

// Dirección de la API (backend). Se puede cambiar con la variable de entorno API_URL
const API_URL = process.env.API_URL || 'http://localhost:4000';

// Configuración del motor de vistas EJS
app.set('view engine', 'ejs');

// Le decimos a Express que sirva los archivos estáticos de la carpeta "public"
app.use(express.static(path.join(__dirname, 'public')));

// Middleware indispensable para procesar los datos enviados por formularios POST (req.body)
// (límite de 2 MB porque el formulario de mascotas envía la foto ya reducida)
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Middleware para procesar solicitudes fetch en formato JSON
app.use(express.json({ limit: '2mb' }));

// ==========================================
//        SESIÓN (cookie con el token de la API)
// ==========================================
const COOKIE = 'token';

function leerCookie(req, nombre) {
    for (const parte of (req.headers.cookie || '').split(';')) {
        const [clave, ...valor] = parte.trim().split('=');
        if (clave === nombre) {
            try { return decodeURIComponent(valor.join('=')); } catch { return null; }
        }
    }
    return null;
}

// Lee los datos del token solo para mostrar la interfaz (quién eres). La API es la que valida de verdad.
function datosToken(token) {
    try {
        const datos = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
        return datos.exp > Date.now() / 1000 ? datos : null;
    } catch {
        return null;
    }
}

function guardarSesion(res, token) {
    res.append('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);
}

function cerrarSesion(res) {
    res.append('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

// Todas las vistas reciben "sesion" (null si no ha iniciado sesión) para ajustar menús y botones
app.use((req, res, next) => {
    const token = leerCookie(req, COOKIE);
    const datos = token ? datosToken(token) : null;
    res.locals.sesion = datos ? { rol: datos.rol } : null;
    next();
});

// Llama a la API enviando el token de la sesión
async function llamarApi(req, metodo, ruta, cuerpo) {
    const opciones = { method: metodo, headers: { 'Content-Type': 'application/json' } };
    const token = leerCookie(req, COOKIE);
    if (token) opciones.headers.Authorization = `Bearer ${token}`;
    if (cuerpo !== undefined) opciones.body = JSON.stringify(cuerpo);

    try {
        const respuesta = await fetch(API_URL + ruta, opciones);
        let datos = {};
        try { datos = await respuesta.json(); } catch { /* respuesta sin JSON */ }
        return { ok: respuesta.ok, status: respuesta.status, datos };
    } catch (error) {
        return { ok: false, status: 502, datos: { error: 'No se pudo conectar con el servidor de la API.' } };
    }
}

// Protege las rutas: exige sesión válida (y opcionalmente uno de los roles indicados)
function requiereRol(...roles) {
    return async (req, res, next) => {
        if (!leerCookie(req, COOKIE)) return res.redirect('/signin');

        const resultado = await llamarApi(req, 'GET', '/api/yo');
        if (resultado.status === 401 || resultado.status === 403) {
            cerrarSesion(res);
            return res.status(resultado.status).render('signin', { error: resultado.datos.error || 'Tu sesión expiró. Inicia sesión de nuevo.' });
        }
        if (!resultado.ok) {
            return res.status(502).render('signin', { error: resultado.datos.error || 'No se pudo conectar con el servidor.' });
        }

        req.usuario = resultado.datos.usuario;
        if (roles.length && !roles.includes(req.usuario.rol)) return res.redirect('/panel');
        next();
    };
}

// Mensajes de aviso que se muestran en el panel después de una acción (van en la URL)
const avisos = (req) => ({ ok: req.query.ok || null, error: req.query.error || null });
const volver = (res, tipo, texto, destino = '/panel') =>
    res.redirect(303, `${destino}?${tipo}=${encodeURIComponent(texto)}`);

// Texto de error de la API (o uno genérico)
const textoError = (resultado) => resultado.datos.error || 'No se pudo completar la acción.';

// ==========================================
//        PÁGINAS PÚBLICAS
// ==========================================

// Ruta Principal (Inicio)
app.get('/', (req, res) => {
    res.render('index');
});

// Ruta para Sobre Nosotros
app.get('/about', (req, res) => {
    res.render('about');
});

// Ruta para Refugios
app.get('/refugios', (req, res) => {
    res.render('refugios');
});

// Ruta para el Catálogo: muestra las mascotas disponibles que registraron los refugios
app.get('/catalogo', async (req, res) => {
    const resultado = await llamarApi(req, 'GET', '/api/mascotas?estado=Disponible');
    const animales = resultado.ok ? resultado.datos.mascotas.map(m => ({ ...m, id: m._id })) : [];
    res.render('catalogo', {
        animales,
        errorCarga: resultado.ok ? null : 'No fue posible cargar el catálogo en este momento.'
    });
});

// Ruta para Iniciar Sesión
app.get('/signin', (req, res) => {
    res.render('signin');
});

// Ruta para Voluntariado
app.get('/voluntariado', (req, res) => {
    res.render('voluntariado');
});

// Ruta para el Registro
app.get('/registro', (req, res) => {
    res.render('registro');
});

// Las peticiones a /api/... (por ejemplo, el formulario de registro y las fotos) se reenvían a la API
app.use('/api', async (req, res) => {
    try {
        const opciones = { method: req.method, headers: { 'Content-Type': 'application/json' } };
        if (req.headers.authorization) opciones.headers.Authorization = req.headers.authorization;
        if (!['GET', 'HEAD'].includes(req.method) && req.body) opciones.body = JSON.stringify(req.body);

        const respuesta = await fetch(API_URL + req.originalUrl, opciones);
        res.status(respuesta.status);
        res.set('Content-Type', respuesta.headers.get('content-type') || 'application/json');
        const cache = respuesta.headers.get('cache-control');
        if (cache) res.set('Cache-Control', cache);
        res.send(Buffer.from(await respuesta.arrayBuffer()));
    } catch (error) {
        res.status(502).json({ error: 'No se pudo conectar con el servidor de la API.' });
    }
});

// ==========================================
//        INICIO Y CIERRE DE SESIÓN
// ==========================================

// La API valida correo y contraseña; el rol (Ciudadano, Refugio o Admin) sale de la base de datos.
// Un refugio no puede entrar hasta que el administrador apruebe su registro.
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const resultado = await llamarApi(req, 'POST', '/api/login', { email, password });

    if (!resultado.ok) {
        return res.status(resultado.status).render('signin', { error: textoError(resultado) });
    }

    guardarSesion(res, resultado.datos.token);
    res.redirect(303, '/panel');
});

app.get('/logout', (req, res) => {
    cerrarSesion(res);
    res.redirect('/');
});

// ==========================================
//        PANEL (según el rol)
// ==========================================
app.get('/panel', requiereRol(), async (req, res) => {
    const base = { email: req.usuario.email, nombre: req.usuario.nombre, ...avisos(req) };
    let resultados;

    if (req.usuario.rol === 'Refugio') {
        resultados = await Promise.all([
            llamarApi(req, 'GET', '/api/mascotas/mias'),
            llamarApi(req, 'GET', '/api/solicitudes/recibidas'),
            llamarApi(req, 'GET', '/api/emergencias/recibidas')
        ]);
        const [mascotas, solicitudes, emergencias] = resultados;
        return res.render('dashboard-refugio', {
            ...base,
            mascotas: mascotas.datos.mascotas || [],
            solicitudes: solicitudes.datos.solicitudes || [],
            emergencias: emergencias.datos.emergencias || [],
            error: base.error || (resultados.find(r => !r.ok) || { datos: {} }).datos.error || null
        });
    }

    if (req.usuario.rol === 'Admin') {
        resultados = await Promise.all([
            llamarApi(req, 'GET', '/api/refugios'),
            llamarApi(req, 'GET', '/api/admin/resumen')
        ]);
        const [refugios, resumen] = resultados;
        return res.render('dashboard-admin', {
            ...base,
            refugios: refugios.datos.refugios || [],
            resumen: resumen.datos || {},
            error: base.error || (resultados.find(r => !r.ok) || { datos: {} }).datos.error || null
        });
    }

    resultados = await Promise.all([
        llamarApi(req, 'GET', '/api/solicitudes/mias'),
        llamarApi(req, 'GET', '/api/emergencias/mias')
    ]);
    const [solicitudes, emergencias] = resultados;
    res.render('dashboard-ciudadano', {
        ...base,
        solicitudes: solicitudes.datos.solicitudes || [],
        emergencias: emergencias.datos.emergencias || [],
        error: base.error || (resultados.find(r => !r.ok) || { datos: {} }).datos.error || null
    });
});

// ==========================================
//        CIUDADANO: solicitud de adopción y reportes de emergencia
// ==========================================

// Formulario para solicitar la adopción de una mascota
app.get('/solicitud/:id', requiereRol('Ciudadano'), async (req, res) => {
    const resultado = await llamarApi(req, 'GET', `/api/mascotas/${encodeURIComponent(req.params.id)}`);
    if (!resultado.ok) return res.redirect('/catalogo');

    const animal = { ...resultado.datos.mascota, id: resultado.datos.mascota._id };
    res.render('solicitud', { animal, error: req.query.error || null });
});

app.post('/solicitud/:id', requiereRol('Ciudadano'), async (req, res) => {
    const id = encodeURIComponent(req.params.id);
    const resultado = await llamarApi(req, 'POST', '/api/solicitudes', {
        mascota_id: req.params.id,
        mensaje: req.body.mensaje
    });
    if (!resultado.ok) return volver(res, 'error', textoError(resultado), `/solicitud/${id}`);
    volver(res, 'ok', resultado.datos.mensaje);
});

// Reporte de emergencia: le llega a todos los refugios aprobados
app.post('/reportar-emergencia', requiereRol('Ciudadano'), async (req, res) => {
    const { tipo_emergencia, ubicacion, descripcion } = req.body;
    const resultado = await llamarApi(req, 'POST', '/api/emergencias', {
        tipo: tipo_emergencia,
        ubicacion,
        descripcion
    });
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', resultado.datos.mensaje);
});

// ==========================================
//        REFUGIO: mascotas, solicitudes y emergencias
// ==========================================

// Publicar una mascota nueva (solo refugios aprobados)
app.post('/mascotas', requiereRol('Refugio'), async (req, res) => {
    const cuerpo = {};
    const campos = { nombre: 'nombre', especie: 'especie', raza: 'raza', edad: 'edad', sexo: 'sexo', tamano: 'tamaño', descripcion: 'descripcion', imagen: 'imagen' };
    for (const [formulario, api] of Object.entries(campos)) {
        const valor = req.body[formulario];
        if (typeof valor === 'string' && valor.trim() !== '') cuerpo[api] = valor.trim();
    }

    const resultado = await llamarApi(req, 'POST', '/api/mascotas', cuerpo);
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', `${resultado.datos.mascota.nombre} ya está publicada en el catálogo de adopciones.`);
});

app.post('/mascotas/:id/eliminar', requiereRol('Refugio'), async (req, res) => {
    const resultado = await llamarApi(req, 'DELETE', `/api/mascotas/${encodeURIComponent(req.params.id)}`);
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', 'La mascota fue eliminada del catálogo.');
});

// Aceptar o rechazar una solicitud de adopción
app.post('/solicitudes/:id/responder', requiereRol('Refugio'), async (req, res) => {
    const resultado = await llamarApi(req, 'PUT', `/api/solicitudes/${encodeURIComponent(req.params.id)}/responder`, {
        decision: req.body.decision,
        respuesta: req.body.respuesta
    });
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', `La solicitud fue ${req.body.decision === 'Aprobada' ? 'aprobada' : 'rechazada'}.`);
});

// Aceptar o rechazar atender un reporte de emergencia
app.post('/emergencias/:id/responder', requiereRol('Refugio'), async (req, res) => {
    const resultado = await llamarApi(req, 'PUT', `/api/emergencias/${encodeURIComponent(req.params.id)}/responder`, {
        decision: req.body.decision
    });
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', resultado.datos.mensaje);
});

// ==========================================
//        ADMINISTRADOR: aprobar o rechazar refugios
// ==========================================
app.post('/admin/refugios/:id/estado', requiereRol('Admin'), async (req, res) => {
    const resultado = await llamarApi(req, 'PUT', `/api/refugios/${encodeURIComponent(req.params.id)}/estado`, {
        estado: req.body.estado
    });
    if (!resultado.ok) return volver(res, 'error', textoError(resultado));
    volver(res, 'ok', `El refugio fue ${req.body.estado === 'Aprobado' ? 'aprobado' : 'rechazado'}.`);
});

// Iniciamos el servidor
app.listen(puerto, () => {
  console.log(`¡Servidor funcionando en http://localhost:${puerto}!`);
});
