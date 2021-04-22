const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const registerValidator = require('../validator/registerValidator')
const loginValidator = require('../validator/loginValidator')
const User = require('../model/User')
const { serverError, resourceError } = require('../util/error')

//login controller
module.exports = {
    login(req, res) {
        //extract data from request
        let { email, password } = req.body

        //validate data
        let validate = loginValidator({ email, password })

        if (!validate.isValid) {
            return res.status(400).json(validate.error)
        }

        //check for user availability
        User.findOne({ email })
            // use populate for transaction
            .then(user => {
                if (!user) {
                    return resourceError(res, 'User not found')
                }
                bcrypt.compare(password, user.password, (err, result) => {
                    if (err) {
                        return serverError(req, err)
                    }
                    if (!result) {
                        return resourceError(res, 'Password Doesn\'t Match ')
                    }

                    let token = jwt.sign({
                        _id: user._id,
                        name: user.name,
                        email: user.email,
                        amount: user.amount,
                        income: user.income,
                        expense: user.expense,
                        transactions: user.transactions,
                    }, 'SECRET', { expiresIn: '2h' })

                    res.status(200).json({
                        message: 'Login Successful',
                        token: `Bearer ${token}`
                    })
                })
            })
            .catch(error => serverError(res, error))
        //compare password
        //generate token and response back
    },
    register(req, res) {
        //read client data
        let { name, email, password, confirmPassword } = req.body

        //validation check user data
        let validate = registerValidator({ name, email, password, confirmPassword })

        if (!validate.isValid) {
            return res.status(400).json(validate.error)
        } else {
            User.findOne({ email })
                .then(user => {
                    if (user) {
                        return resourceError(res, 'Email already exists')
                    }

                    bcrypt.hash(password, 11, (err, hash) => {
                        if (err) {
                            return resourceError(res, 'Server error occurred')
                        }

                        let user = new User({
                            name,
                            email,
                            password: hash,
                            balance: 0,
                            expense: 0,
                            income: 0,
                            transactions: []
                        })

                        user.save()
                            .then(user => {
                                res.status(201).json({
                                    message: 'User created successfully',
                                    user
                                })
                            })
                            .catch(error => serverError(res, error))
                    })
                })
                .catch(error => serverError(res, error))
        }
        //check for duplicate user
        //new user object
        //save to database
        //response back with new data
    },
    allUser(req, res) {
        User.find()
            .then(users => {
                res.status(200).json(users)
            })
            .catch(error => serverError(res, error))
    }
}