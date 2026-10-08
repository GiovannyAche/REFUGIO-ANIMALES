const mongoose = require('mongoose');

// Definición de la estructura de la colección 'usuarios'
const usuarioSchema = new mongoose.Schema({
    nombre: { 
        type: String, 
        required: true,
        trim: true // Elimina espacios en blanco al inicio y al final
    },
    email: { 
        type: String, 
        required: true,
        unique: true, // Garantiza que no existan dos cuentas con el mismo correo
        trim: true,
        lowercase: true
    },
    password: { 
        type: String, 
        required: true,
        select: false // No se devuelve en las consultas; el login la pide explícitamente
    },
    rol: { 
        type: String, 
        enum: ['Ciudadano', 'Refugio', 'Admin'],
        default: 'Ciudadano' 
    },
    telefono: { 
        type: String,
        trim: true
    },
    direccion: { 
        type: String // Muy útil para geolocalizar los Refugios en Bogotá
    },
    // Este campo es vital para el control del Administrador sobre los Refugios
    estado_aprobacion: { 
        type: String, 
        enum: ['Pendiente', 'Aprobado', 'Rechazado', 'Suspendido'],
        default: 'Aprobado' // Un ciudadano nace "Aprobado", un refugio nace "Pendiente" hasta que el administrador lo apruebe
    }
}, {
    timestamps: true, // Registra fecha de creación y última actualización
    toJSON: {
        // Nunca incluir la contraseña (hash) en las respuestas JSON
        transform: (doc, ret) => {
            delete ret.password;
            delete ret.__v;
            return ret;
        }
    }
});

// Exportar el modelo
module.exports = mongoose.model('Usuario', usuarioSchema);