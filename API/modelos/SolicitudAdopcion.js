const mongoose = require('mongoose');

// Solicitud de adopción: la envía un ciudadano y la responde el refugio dueño de la mascota
const solicitudSchema = new mongoose.Schema({
    mascota_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Mascota',
        required: true
    },
    ciudadano_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario',
        required: true
    },
    // Refugio que tiene la mascota: es quien acepta o rechaza la solicitud
    refugio_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario',
        required: true
    },
    mensaje: {
        type: String,
        required: true,
        trim: true,
        maxlength: 1000
    },
    estado: {
        type: String,
        enum: ['Pendiente', 'Aprobada', 'Rechazada'],
        default: 'Pendiente'
    },
    // Mensaje opcional del refugio al responder
    respuesta: {
        type: String,
        trim: true,
        maxlength: 500
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('SolicitudAdopcion', solicitudSchema, 'solicitudes_adopcion');
