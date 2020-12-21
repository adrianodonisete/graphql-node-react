const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Post = require('../models/post');

const { clearImage } = require('../util/file');
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
	createPost: async function ({ postInput }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}

		let errors = [];
		if (
			validator.isEmpty(postInput.title) ||
			!validator.isLength(postInput.title, { min: 5 })
		) {
			errors.push[{ message: 'Invalid title.' }];
		}
		if (
			validator.isEmpty(postInput.content) ||
			!validator.isLength(postInput.content, { min: 5 })
		) {
			errors.push[{ message: 'Invalid content.' }];
		}
		console.log(errors);
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			error.code = 422;
			throw error;
		}

		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('Invalid user.');
			error.code = 401;
			throw error;
		}

		//'5fdffd17ad9d0a23041300fb'
		const post = new Post({
			title: postInput.title,
			content: postInput.content,
			imageUrl: postInput.imageUrl,
			creator: user,
		});
		const createdPost = await post.save();
		user.posts.push(createdPost);
		await user.save();

		return {
			...createdPost._doc,
			_id: createdPost._id.toString(),
			createdAt: createdPost.createdAt.toISOString(),
			updatedAt: createdPost.updatedAt.toISOString(),
		};
	},
	posts: async function ({ page }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		if (!page) {
			page = 1;
		}
		const perPage = 2;
		const totalPosts = await Post.find().countDocuments();
		const posts = await Post.find()
			.sort({ createdAt: -1 })
			.skip((page - 1) * perPage)
			.limit(perPage)
			.populate('creator');

		return {
			posts: posts.map(p => {
				return {
					...p._doc,
					_id: p._id.toString(),
					createdAt: p.createdAt.toISOString(),
					updatedAt: p.updatedAt.toISOString(),
				};
			}),
			totalPosts,
		};
	},
	post: async function ({ id }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found!');
			error.code = 404;
			return error;
		}
		return {
			...post._doc,
			_id: post._id.toString(),
			createdAt: post.createdAt.toISOString(),
			updatedAt: post.updatedAt.toISOString(),
		};
	},
	updatePost: async function ({ id, postInput }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found!');
			error.code = 404;
			return error;
		}
		if (post.creator._id.toString() !== req.userId.toString()) {
			const error = new Error('Not authorized!');
			error.code = 403;
			return error;
		}

		const errors = [];
		if (
			validator.isEmpty(postInput.title) ||
			!validator.isLength(postInput.title, { min: 5 })
		) {
			errors.push[{ message: 'Invalid title.' }];
		}
		if (
			validator.isEmpty(postInput.content) ||
			!validator.isLength(postInput.content, { min: 5 })
		) {
			errors.push[{ message: 'Invalid content.' }];
		}
		console.log(errors);
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			error.code = 422;
			throw error;
		}
		post.title = postInput.title;
		post.content = postInput.content;
		if (postInput.imageUrl !== 'undefined') {
			post.imageUrl = postInput.imageUrl;
		}
		const updatedPost = await post.save();

		return {
			...updatedPost._doc,
			_id: updatedPost._id.toString(),
			createdAt: updatedPost.createdAt.toISOString(),
			updatedAt: updatedPost.updatedAt.toISOString(),
		};
	},
	deletePost: async function ({ id }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		const post = await Post.findById(id);
		if (!post) {
			const error = new Error('No post found!');
			error.code = 404;
			throw error;
		}
		if (post.creator.toString() !== req.userId.toString()) {
			const error = new Error('Not authorized!');
			error.code = 403;
			throw error;
		}
		clearImage(post.imageUrl);
		await Post.findByIdAndRemove(id);
		const user = await User.findById(req.userId);
		user.posts.pull(id);
		await user.save();
		return true;
	},
	user: async function (_, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('No user found!');
			error.code = 404;
			throw error;
		}
		return {
			...user._doc,
			_id: user._id.toString(),
		};
	},
	updateStatus: async function ({ status }, req) {
		const error = isAuth(req);
		if (error) {
			throw error;
		}
		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('No user found!');
			error.code = 404;
			throw error;
		}
		user.status = status;
		await user.save();
		return {
			...user._doc,
			_id: user._id.toString(),
		};
	},
	findName: function ({ name }) {
		return {
			token: 'asdfa ' + jwtConfig.secret,
			userId: `Nome enviado: ${name}`,
		};
	},
};

function isAuth(req) {
	if (!req.isAuth) {
		const error = new Error('Not authenticated!');
		error.code = 401;
		return error;
	}
	return null;
}
