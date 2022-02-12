const bcrypt = require('bcrypt');
const uuid = require('uuid');
const UserModel = require('../model/user-model');
const mailService = require('../service/mail-service');
const tokenService = require('../service/token-service');
const UserDto = require('../dtos/user-dto');
const ApiError = require('../exeptions/api-error');

class userService {
    async registration (email, password) {
        const candidate = await UserModel.findOne({ email });
        if (candidate) {
            throw ApiError.BadRequest(`Пользователь с таким адресом ${email} уже существует!!!!`);
        }

        const hashPassword = await bcrypt.hash(password, 3);
        const activationLink = uuid.v4();

        const user = await UserModel.create({ email, password: hashPassword, activationLink });

        await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`);

        const userDto = new UserDto(user);
        const tokens = tokenService.generateToken({...userDto});

        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return {...tokens, user: userDto };
    }

    async activate (activationLink) {
        const user = await UserModel.findOne({ activationLink });

        if (!user) {
            throw ApiError.BadRequest('Некорректная ссылка для активации');
        }

        user.isActivated = true; // лучше храть эти данные в другой коллекции
        await user.save()
    }

    async login (email, password) {
        const user = await UserModel.findOne({ email });

        if (!user) {
            throw ApiError.BadRequest('Пользователь с такой почтой не найден :(');
        }

        const isPassEquals = await bcrypt.compare(password, user.password);

        if (!isPassEquals) {
            throw ApiError.BadRequest('Неверный пароль');
        }

        const userDto = new UserDto(user);
        const tokens = tokenService.generateToken({ ...userDto });
        await tokenService.saveToken(userDto.id, tokens.refreshToken); // тут логика дублируется поэтому можно вынести в отдельную функцию

        return {...tokens, user: userDto };
    }

    async logOut (refreshToken) {
        const token = await tokenService.removeToken(refreshToken);

        return token;
    }

    async refresh (refreshToken) {
        if (!refreshToken) {
            throw ApiError.UnAuthorizedError();
        }

        const userData = tokenService.validateRefreshToken(refreshToken);
        const tokenFromDb = await tokenService.findToken(refreshToken);

        if (!userData || !tokenFromDb) {
            throw ApiError.UnAuthorizedError();
        }

        const user = await UserModel.findById(userData.id)
        const userDto = new UserDto(user);
        const tokens = tokenService.generateToken({ ...userDto });
        await tokenService.saveToken(userDto.id, tokens.refreshToken); // тут логика дублируется поэтому можно вынести в отдельную функцию

        return {...tokens, user: userDto };
    }

    async getAllusers () {
        const users = await UserModel.find();
        return users;
    }
}

module.exports = new userService();