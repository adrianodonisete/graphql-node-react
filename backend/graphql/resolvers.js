const bcrypt = require('bcryptjs');
const validator = require('validator');

const User = require('../models/user');

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
			const error = new Erroror('Invalid input.');
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

	// hello() {
	// 	return {
	// 		text: 'Hello World!',
	// 		views: 1234,
	// 	};
	// },
};
