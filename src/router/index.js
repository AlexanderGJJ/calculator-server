const Router = require("express").Router;
const userController = require("../controller/user-controller");
const router = new Router();
const { body } = require("express-validator");
const authMiddleware = require("../middlewares/auth-middleware");

router.post(
  "/registration",
  body("email").isEmail(),
  body("password").isLength({ min: 3, max: 30 }),
  userController.registration
);

router.post("/login", userController.login);
router.post("/logout", userController.logOut);
router.get("/activate/:link", userController.activate);
router.get("/refresh", userController.refresh);

module.exports = router;
