const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const jwtConfig = require('../../config/jwt');

module.exports = {
	createUser: async function ({ userInput }, req) {
		let errors = [];
		if (!validator.isEmail(userInput.email)) {
			errors.push[{ message: 'E-Mail is invalid.' }];
		}
		if (
			validator.isEmpty(userInput.password) ||
			!validator.isLength(userInput.password, { min: 5 })
		) {
			errors.push[{ message: 'Password too short.' }];
		}
		console.log(errors);
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			error.code = 422;
			throw error;
		}

		const existingUser = await User.findOne({ email: userInput.email });
		if (existingUser) {
			throw new Error('User exists already!');
		}
		const hashedPw = await bcrypt.hash(userInput.password, 12);
		const user = new User({
			email: userInput.email,
			name: userInput.name,
			password: hashedPw,
		});
		const createdUser = await user.save();
		return { ...createdUser._doc, _id: createdUser._id.toString() };
	},
	login: async function ({ email, password }) {
		const user = await User.findOne({ email });
		if (!user) {
			const error = new Error('User or Password is incorrect 1.');
			error.code = 401;
			throw error;
		}
		const isEqual = await bcrypt.compare(password, user.password);
		if (!isEqual) {
			const error = new Error('User or Password is incorrect 2.');
			error.code = 401;
			throw error;
		}

		const token = jwt.sign(
			{
				userId: user._id.toString(),
				email: user.email,
			},
			jwtConfig.secret,
			{ expiresIn: '1h' }
		);
		return { token, userId: user._id.toString() };
	},
};
