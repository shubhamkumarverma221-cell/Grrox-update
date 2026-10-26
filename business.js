const mongoose = require("mongoose");

const businessSchema = new mongoose.Schema(
    {
        ownerName: {
            type: String,
            required: true,
            trim: true
        },

        mobile: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },

        businessName: {
            type: String,
            required: true,
            trim: true
        },

        category: {
            type: String,
            required: true
        },

        address: {
            type: String,
            required: true,
            trim: true
        },

        city: {
            type: String,
            required: true,
            trim: true
        },

        area: {
            type: String,
            required: true,
            trim: true
        },

        pincode: {
            type: String,
            required: true,
            trim: true
        },

        verificationStatus: {
            type: String,
            default: "Unverified"
        },

        settings: {
            type: Object,
            default: {}
        },

        shopStatus: {
            type: String,
            default: "Open"
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Business", businessSchema);