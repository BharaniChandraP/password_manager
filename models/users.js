const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  passwords: [{ 
    application: String, // Name of the application/service
    username: String,
    password: String
  }]
  
});

module.exports = mongoose.model('User', userSchema);

