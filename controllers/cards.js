const Card = require('../models/card');

/**получить все карточки */
module.exports.getCards=(req, res) => {
  Card.find({})
    .then(card => res.send({ data: card }))
    .catch(err => res.status(500).send({ message: 'Произошла ошибка' }));
};

/** создать карточку */
module.exports.createCard = (req, res) => {
  const { name, link } = req.body;
  const owner = req.user._id;
  Card.create({ name, link, owner })
    .then(card => res.send({ data: card }))
    .catch(err => res.status(500).send({ message: 'Произошла ошибка' }));
};

/** удалить карточку по ID */
module.exports.deleteCard = (req, res)=>{
  Card.findByIdAndRemove(req.params.CardId)
    .then(card => res.send({ data: card }))
    .catch(err => res.status(500).send({ message: 'Произошла ошибка' }));
};

/** поставить лайк карточке */
module.exports.likeCard = (req, res)=>{

  Card.findByIdAndUpdate(  req.params.cardId, { $addToSet: { likes: req.user._id } }, { new: true })
    .then(card => res.send({ data: card }))
    .catch(err => res.status(500).send({ message: 'Произошла ошибка' }));
};

/** удалить лайк у карточки */
module.exports.dislikeCard = (req, res)=>{
  Card.findByIdAndUpdate(req.params.cardId, { $pull: { likes: req.user._id } }, { new: true })
    .then(card => res.send({ data: card }))
    .catch(err => res.status(500).send({ message: 'Произошла ошибка' }));
};

