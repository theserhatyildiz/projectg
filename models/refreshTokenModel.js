const mongoose = require('mongoose');
const crypto = require('crypto'); // To hash the token for added security

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // This refers to the User model
    required: true,
  },
  expiryDate: {
    type: Date,
    required: true,
  },
});

// Method to check if the refresh token is expired
refreshTokenSchema.methods.isExpired = function() {
  return Date.now() >= this.expiryDate;
};

// Method to hash the token (optional, but recommended for security)
refreshTokenSchema.pre('save', function(next) {
  if (this.isModified('token')) {
    this.token = crypto.createHash('sha256').update(this.token).digest('hex');
  }
  next();
});

// Indexing for faster query performance
refreshTokenSchema.index({ userId: 1, expiryDate: 1 });

// Method to create a hashed token
refreshTokenSchema.statics.createToken = function(userId, expiryDate) {
  const token = crypto.randomBytes(40).toString('hex'); // Create a random token
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex'); // Hash the token
  
  return new this({
    token: hashedToken,
    userId,
    expiryDate
  });
};

// Static method to verify a token (compare hashed version)
refreshTokenSchema.statics.verifyToken = async function(token, userId) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const foundToken = await this.findOne({ token: hashedToken, userId });
  
  if (!foundToken) return null;
  
  if (foundToken.isExpired()) {
    await foundToken.remove(); // Remove expired tokens
    return null;
  }

  return foundToken;
};

const refreshTokenModel = mongoose.model('refreshTokens', refreshTokenSchema);

module.exports = refreshTokenModel;