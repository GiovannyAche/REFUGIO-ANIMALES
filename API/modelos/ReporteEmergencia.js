const mongoose = require('mongoose');

// Reporte de emergencia: lo envía un ciudadano y le llega a todos los refugios aprobados.
// El primer refugio que lo acepta se encarga del caso; cada refugio puede rechazarlo por su cuenta.
const reporteSchema = new mongoose.Schema({
    ciudadano_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario',
        required: true
    },
    tipo: {
        type: String,
        enum: ['atropellado', 'maltrato', 'abandono'],
        required: true
    },
    ubicacion: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200
    },
    descripcion: {
        type: String,
        required: true,
        trim: true,
        maxlength: 1000
    },
    estado: {
        type: String,
        enum: ['Pendiente', 'Aceptada'],
        default: 'Pendiente'
    },
    // Refugio que aceptó atender el caso
    atendido_por: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario'
    },
    // Refugios que dijeron que no pueden atenderlo (dejan de verlo en su lista)
    rechazado_por: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario'
    }]
}, {
    timestamps: true
});

module.exports = mongoose.model('ReporteEmergencia', reporteSchema, 'reportes_emergencia');
