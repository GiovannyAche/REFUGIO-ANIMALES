const mongoose = require('mongoose');

// Definición de la estructura de la colección 'mascotas'
const mascotaSchema = new mongoose.Schema({
    nombre: { 
        type: String, 
        required: true,
        trim: true 
    },
    especie: { 
        type: String, 
        required: true,
        enum: ['Perro', 'Gato', 'Otro'] // Validación estricta
    },
    raza: { 
        type: String, 
        default: 'Criollo/Mestizo' 
    },
    edad: { 
        type: String, 
        required: true 
    },
    sexo: { 
        type: String, 
        enum: ['Macho', 'Hembra'],
        required: true 
    },
    tamaño: { 
        type: String, 
        enum: ['Pequeño', 'Mediano', 'Grande'] 
    },
    descripcion: { 
        type: String, 
        required: true 
    },
    imagen: { 
        type: String, 
        default: '/imagenes/default.jpg' 
    },
    estado: { 
        type: String, 
        enum: ['Disponible', 'En proceso', 'Adoptado'],
        default: 'Disponible' 
    },
    refugio_id: {
        // A futuro, esto vinculará a la mascota con un refugio específico
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario'
    },
    fecha_registro: { 
        type: Date, 
        default: Date.now 
    }
}, {
    timestamps: true // Crea automáticamente campos createdAt y updatedAt
});

// Exportar el modelo para usarlo en las rutas
module.exports = mongoose.model('Mascota', mascotaSchema);