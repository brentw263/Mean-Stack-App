var mongoose = require('mongoose');
var Schema   = mongoose.Schema;
var bcrypt   = require('bcrypt-nodejs');
var titlize  = require('mongoose-title-case');
var validate = require('mongoose-validators');

var nameValidator = [
	validate.matches({ message: 'Name must be at 3 characters, max 40, no special characters or numbers, must have space in between name.' },/^(([a-zA-Z]{3,20})+[ ]+([a-zA-Z]{3,20})+)+$/),
	validate.isLength({ message: 'Email should be between {ARGS[0]} and {ARGS[1]} characters' },3,20)
];

var emailValidator = [
	validate.isEmail({ message: 'Is not a valid e-mail address' }),
	validate.isLength({ message: 'Email should be between {ARGS[0]} and {ARGS[1]} characters' },3,20)
];

var usernameValidator = [
	validate.isAlphanumeric({ message: 'Username should contain only letters or numbers' }),
	validate.isLength({ message: 'Username should be between {ARGS[0]} and {ARGS[1] characters' }, 3,25)
];

var passwordValidator = [
	validate.matches({ message: 'Password needs to have at least one lower case, one uppercase, at least 8 characters, max 35.' },/^(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[\d])(?=.*?[\W]).{8,35}$/),
	validate.isLength({ message: 'Password should be between {ARGS[0]} and {ARGS[1]} characters' },8,35)
];

var UserSchema = new Schema({
	name: { type: String, required: true, validate: nameValidator },
	username : { type: String, required: true, lowercase: true,  unique: true, validate: usernameValidator },
	password : { type: String, required: true, validate: passwordValidator, select: false },
	email : { type: String, required: true, lowercase: true, unique: true, validate: emailValidator },
	active : { type: Boolean, required: true, default: false },
	temporarytoken: { type: String, required: true },
	resettoken: { type: String, required: false },
	permission: { type: String, required: true, default: 'user' }
});


UserSchema.pre('save', function(next) {
  var user = this;

  if (!user.isModified('password')) return next();
  
  bcrypt.hash(user.password, null, null, function(err,hash){
	  if (err) return next(err);
	  user.password = hash;
	  next();
  });
});

UserSchema.plugin(titlize, {
  paths: [ 'name' ]
});

UserSchema.methods.comparePassword = function(password){
	return bcrypt.compareSync(password, this.password);
};


module.exports = mongoose.model('User', UserSchema);