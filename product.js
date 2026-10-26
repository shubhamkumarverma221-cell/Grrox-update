const mongoose = require("mongoose");

const productSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true
        },

        price: {
            type: Number,
            required: true
        },

        originalPrice: {
            type: Number,
            default: 0
        },

        image: {
            type: String,
            default: ""
        },

        description: {
            type: String,
            default: ""
        },

        category: {
            type: String,
            default: "Other"
        },

        shopName: {
            type: String,
            default: "Local GRROX Shop"
        },

        businessId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Business",
            default: null
        },

        offer: {
            type: String,
            default: "DEAL"
        },

        icon: {
            type: String,
            default: "🛍️"
        },

        city: {
            type: String,
            default: "Jaipur"
        },

        views: { type: Number, default: 0 },

        claims: { type: Number, default: 0 },

        link: {
            type: String,
            default: ""
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Product", productSchema);