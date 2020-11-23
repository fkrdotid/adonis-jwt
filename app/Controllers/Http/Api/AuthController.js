const Hash = use('Hash');
const { validate } = use('Validator');
const Encryption = use('Encryption');
const User = use('App/Models/User');
const Token = use('App/Models/Token');

class AuthController {
  async signIn({ request, response, auth }) {
    
    const { email, password } = request.only(['email', 'password']);

    if (email) {
      try {
        return await auth.withRefreshToken().attempt(email, password);
      } catch (err) {
        response.status(401).send({ error: 'Invalid email or password' });
      }
    } else {
      response.status(401).send(validation.messages());
    }
  }

  async register({ request, response }) {
    
  
    const { email, username, password } = request.only([
      'email',
      'username',
      'password'
    ]);

  
    if (email) {
      try {
        const user = await User.create({ email, username, password });
        return response.send({ message: 'User has been created' });
      } catch (err) {
        response.status(401).send({ error: 'Please try again' });
      }
    } else {
      response.status(401).send(validation.messages());
    }
  }

  async refreshToken({ request, response, auth }) {
    

    const { refresh_token } = request.only(['refresh_token']);

    if (refresh_token) {
      try {
        return await auth
          .newRefreshToken()
          .generateForRefreshToken(refresh_token);
      } catch (err) {
        response.status(401).send({ error: 'Invalid refresh token' });
      }
    } else {
      response.status(401).send(validation.messages());
    }
  }

  async logout({ request, response, auth }) {
  
    const { refresh_token } = request.only(['refresh_token']);

    const decrypted = Encryption.decrypt(refresh_token);

    if (refresh_token) {
      try {
        const refreshToken = await Token.findBy('token', decrypted);
        if (refreshToken) {
          refreshToken.delete();
          response.status(200).send({ status: 'ok' });
        } else {
          response.status(401).send({ error: 'Invalid refresh token' });
        }
      } catch (err) {
        response.status(401).send({ error: 'something went wrong' });
      }
    } else {
      response.status(401).send(validation.messages());
    }
  }
}

module.exports = AuthController;
