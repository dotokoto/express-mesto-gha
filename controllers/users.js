const User = require('../models/user');
const { CAST_ERROR, NOT_FOUND_ERROR, SERVER_ERROR } = require('../utils/constants');

/** получить всех пользователей */
module.exports.getUsers = (req, res) => {
  User.find({})
    .then((user) => {
      res.status(200).send({ data: user })
    })
    .catch((err) => {
      res.status(SERVER_ERROR).send({ message: 'На сервере произошла ошибка' }),
    });
};

/**получить пользователя по ID */
module.exports.getUserById= async (req, res) => {
  const userId = req.params.userId;
  try{
    const user = await User.findById(userId)
    if(!user){
      res.status(NOT_FOUND_ERROR).send({message: 'Пользователь по указанному id не найден'});
      return
    }
    res.status(200).send({ data: user });
  }catch(err){
    if(err.name === "CastError"){
      res.status(CAST_ERROR).send({message: 'Введен некорректный id пользователя'});
      return
    }else{
      res.status(SERVER_ERROR).send({message: 'На сервере произошла ошибка'})
    }
  };
};

/** добавить пользователя */
module.exports.createUser = (req, res) => {
  const { name, about, avatar } = req.body;
  User.create({ name, about, avatar })
    .then((user)=>{res.status(200).send({ data: user });})
    .catch((err) => {
      if(err.name === "ValidationError" || err.name === "CastError"){
        res.status(CAST_ERROR).send({message: 'Введены некорректные данные пользователя'});
        return
      }
      res.status(SERVER_ERROR).send({ message: 'На сервере произошла ошибка' })
    });
};

/** обновить данные пользователя */
module.exports.updateUser = (req, res)=>{
  const { name, about } = req.body;
  const userId = req.user._id;
  User.findByIdAndUpdate(userId, { name, about }, { new: true, runValidators: true })
    .then(user => res.status(200).send({ data: {name, about} }))
    .catch((err)=> {
      if(err.name === "Not Found") {
        res.status(NOT_FOUND_ERROR).send({ message: 'Пользователь по указанному id не найден' });
        return
      }
      if(err.name === "ValidationError" || err.name === "CastError"){
        res.status(CAST_ERROR).send({message: 'Введены некорректные данные пользователя'});
        return
      }
      res.status(SERVER_ERROR).send({message: 'На сервере произошла ошибка'})
    });
};

/** обновить аватар пользователя */
module.exports.updateAvatar = (req, res)=>{
  const { avatar } = req.body;
  const userId = req.user._id;
  User.findByIdAndUpdate(userId, { avatar }, { new: true, runValidators: true })
    .then(user => res.status(200).send({ data: {avatar} }))
    .catch((err) => {
      if(err.name === "Not Found") {
        res.status(NOT_FOUND_ERROR).send({ message: 'Пользователь по указанному id не найден' });
        return
      }
      if(err.name === "ValidationError" || err.name === "CastError"){
        res.status(CAST_ERROR).send({message: 'Введены некорректные данные пользователя'});
        return
      }
      res.status(SERVER_ERROR).send({message: 'На сервере произошла ошибка'})
    });
};
