const mongoose = require('mongoose');

const weightSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    weight: {
        type: Number,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    choice: {
        type: String,
        enum: ['✅', '❌'], // Define the possible values for the choice
        required: true
    }
}, { timestamps: true });

const weightModel = mongoose.model("weights", weightSchema);

module.exports = weightModel;
