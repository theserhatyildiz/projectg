const mongoose = require('mongoose');

const trackingSchema = mongoose.Schema({
    userId:{
        type:mongoose.Schema.Types.ObjectId, 
        ref:'users',
        required:true
    },
    foodId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:'foods',
        required:true
    },
    details:{
        Name: { // Add a new property named "Name" here
            type: String,
          },
          foodId: { // Add foodId property here
            type: mongoose.Schema.Types.ObjectId,
            ref: 'foods',
        },
        Calorie:Number,
        Protein:Number,
        Carbohydrate:Number,
        Fat:Number,
        Fiber:Number,
       
    },
    eatenDate:{
        type:String,
        default:new Date().toLocaleDateString()
    },
    quantity:{
        type:Number,
        min:1,
        required:true
    },
    mealNumber: {
        type: Number,
        required: true
    }
},{timestamps:true})

const trackingModel = mongoose.model("trackings", trackingSchema);

module.exports = trackingModel;