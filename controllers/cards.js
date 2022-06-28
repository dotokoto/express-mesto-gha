const Card = require('../models/card');
const CastError = require('../errors/cast-error');
const NotFoundError = require('../errors/not-found-error');

/** получить все карточки */
module.exports.getCards = (req, res, next) => {
  Card.find({})
    .then((cards) => {
      res.status(200).send({ data: cards });
    })
    .catch(next);
};

/** создать карточку */
module.exports.createCard = async (req, res, next) => {
  const { name, link } = req.body;
  const owner = req.user._id;
  try {
    const card = await Card.create({ name, link, owner });
    res.status(201).send({ data: card });
  } catch (err) {
    if (err.name === 'ValidationError') {
      next(new CastError('Введены некорректные данные'));
    }
    next();
  }
};

/** удалить карточку по ID */
module.exports.deleteCard = (req, res, next) => {
  const { cardId } = req.params;
  Card.findByIdAndRemove(cardId)
    .then((card) => {
      if (!card) {
        throw new NotFoundError('Карточка с указанным id не найдена');
      }
      res.status(200).send({ data: card });
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        next(new CastError('Введены некорректные данные'));
      }
      next();
    });
};

/** поставить лайк карточке */
module.exports.likeCard = (req, res, next) => {
  const { cardId } = req.params;
  const userId = req.user._id;
  Card.findByIdAndUpdate(cardId, { $addToSet: { likes: userId } }, { new: true })
    .then((card) => {
      if (!card) {
        throw new NotFoundError('Карточка с указанным id не найдена');
      }
      res.status(200).send({ data: card });
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        next(new CastError('Введены некорректные данные'));
      }
      next();
    });
};

/** удалить лайк у карточки */
module.exports.dislikeCard = (req, res, next) => {
  const { cardId } = req.params;
  const userId = req.user._id;
  Card.findByIdAndUpdate(cardId, { $pull: { likes: userId } }, { new: true })
    .then((card) => {
      if (!card) {
        throw new NotFoundError('Карточка с указанным id не найдена');
      }
      res.status(200).send({ data: card });
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        next(new CastError('Введены некорректные данные'));
      }
      next();
    });
};
