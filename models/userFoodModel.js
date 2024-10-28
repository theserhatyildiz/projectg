const mongoose = require('mongoose');

const userFoodSchema = mongoose.Schema({
    
    NameTr: {
        type: String,  
        required: true 
    },
    Protein: {
        type: Number,
        required: true 
    },
    Carbohydrate: {
        type: Number,
        required: true        
    },
    Fat: {
        type: Number,
        required: true        
    },
    Fiber: {
        type: Number,
        required: true        
    },
    Calorie: {
        type: Number,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
        },

},{timestamps:true});

const foodModel = mongoose.model("userFoods", userFoodSchema);

module.exports = foodModel;