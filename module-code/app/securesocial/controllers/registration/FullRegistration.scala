package securesocial.controllers.registration

import play.api.mvc.{ Result, Action, Controller }
import play.api.mvc.Results._
import play.api.data._
import play.api.data.Forms._
import play.api.data.validation.Constraints._
import play.api.{ Play, Logger }
import securesocial.core.providers.UsernamePasswordProvider
import securesocial.core._
import com.typesafe.plugin._
import Play.current
import securesocial.core.providers.utils._
import org.joda.time.DateTime
import play.api.i18n.Messages
import securesocial.core.providers.Token
import scala.Some
import securesocial.core.IdentityId
import securesocial.controllers.TemplatesPlugin
import securesocial.controllers.ProviderController
import securesocial.controllers.ProviderController.landingUrl

object FullRegistration extends Controller with securesocial.core.SecureSocial {
  import DefaultRegistration.{
    RegistrationInfo,
    UserName,
    UserNameAlreadyTaken,
    providerId,
    FirstName,
    LastName,
    Password,
    Password1,
    Password2,
    PasswordsDoNotMatch,
    Email,
    Success,
    SignUpDone,
    onHandleStartSignUpGoTo,
    ThankYouCheckEmail,
    TokenDurationKey,
    DefaultDuration,
    TokenDuration,
    createToken,
    executeForToken
  }

  val NotActive = "NotActive"
  val EmailAlreadyTaken = "securesocial.signup.emailAlreadyTaken"

  case class FullRegistrationInfo(userName: Option[String], firstName: String, lastName: String, email: String, password: String)

  val formWithUsername = Form[FullRegistrationInfo](
    mapping(
      UserName -> nonEmptyText.verifying(Messages(UserNameAlreadyTaken), userName => {
        UserService.find(IdentityId(userName, providerId)).isEmpty
      }),
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      (Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(use[PasswordValidator].errorMessage,
            p => use[PasswordValidator].isValid(p)),
          Password2 -> nonEmptyText).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2))) // binding
          ((userName, firstName, lastName, email, password) => FullRegistrationInfo(Some(userName), firstName, lastName, email, password._1)) // unbinding
          (info => Some(info.userName.getOrElse(""), info.firstName, info.lastName, info.email, ("", ""))))

  val formWithoutUsername = Form[FullRegistrationInfo](
    mapping(
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      (Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(use[PasswordValidator].errorMessage,
            p => use[PasswordValidator].isValid(p)),
          Password2 -> nonEmptyText).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2))) // binding
          ((firstName, lastName, email, password) => FullRegistrationInfo(None, firstName, lastName, email, password._1)) // unbinding
          (info => Some(info.firstName, info.lastName, info.email, ("", ""))))

  val form = if (UsernamePasswordProvider.withUserNameSupport) formWithUsername else formWithoutUsername

  def signUp = Action { implicit request =>
    if (Logger.isDebugEnabled) {
      Logger.debug("[securesocial] trying sign up")
    }
    Ok(use[TemplatesPlugin].getFullSignUpPage(request, form))
  }

  /**
   * Handles posts from the sign up page
   */

  def handleSignUp = Action { implicit request =>
    form.bindFromRequest.fold(
      errors => {
        if (Logger.isDebugEnabled) {
          Logger.debug("[securesocial] errors " + errors)
        }
        BadRequest(use[TemplatesPlugin].getFullSignUpPage(request, errors))
      },
      info => {
        UserService.findByEmailAndProvider(info.email, providerId) match {
          case None =>
            val id = info.email
            val user = SocialUser(
              IdentityId(id, providerId),
              info.firstName,
              info.lastName,
              "%s %s".format(info.firstName, info.lastName),
              NotActive,
              false,
              Some(info.email),
              GravatarHelper.avatarFor(info.email),
              AuthenticationMethod.UserPassword,
              passwordInfo = Some(Registry.hashers.currentHasher.hash(info.password)))
            UserService.save(user)
            val eventSession = Events.fire(new SignUpEvent(user)).getOrElse(session)
            val token = createToken(info.email, isSignUp = true)
            Mailer.sendVerificationEmail(info.email, token._1)
            if ( UsernamePasswordProvider.signupSkipLogin ) {
              ProviderController.completeAuthentication(user, eventSession).flashing(Success -> Messages(SignUpDone))
            } else {
              Redirect(onHandleStartSignUpGoTo).flashing(Success -> Messages(ThankYouCheckEmail), Email -> info.email)
            }
          case Some(alreadyRegisteredUser) =>
            Redirect(RoutesHelper.fullSignUp().url).flashing(DefaultRegistration.Error -> Messages(EmailAlreadyTaken), Email -> info.email)
        }

      })
  }

  def handleResendEmail = Action { implicit request =>
    if (SecureSocial.currentUser.isDefined) {
      val user = SecureSocial.currentUser.get
      UserService.findTokenForUserEmail(user.email.get) match {
        case None =>
          val newToken = createToken(user.email.get, isSignUp = true)
          Mailer.sendVerificationEmail(user.email.get, newToken._1);
        case Some(token) =>
          Mailer.sendVerificationEmail(user.email.get, token.uuid);
      }
      Redirect(landingUrl).flashing(Success -> Messages("securesocial.email.sent"));
    } else {
      Unauthorized("Not Authorized Page")
    }
  }

  def signUpVerification(token: String) = UserAwareAction { implicit request =>
    def markAsActive(user: Identity) {
      val updated = UserService.verifyUserEmail(SocialUser(user).copy(state = "Active"))
      if (updated.isDefined) {
        Mailer.sendWelcomeEmail(updated.get)
        val eventSession = Events.fire(new SignUpEvent(updated.get)).getOrElse(session)
        ProviderController.completeAuthentication(updated.get, eventSession).flashing(Success -> Messages(SignUpDone))
      }
    }
    executeForToken(token, true, { t =>
      val email = t.email
      val providerId = t.uuid
      val userFromToken = UserService.findByEmailAndProvider(email, UsernamePasswordProvider.UsernamePassword)
      (userFromToken, request.user) match {
        case (Some(user), Some(user2)) if user.identityId == user2.identityId =>
          markAsActive(user)
          Redirect(landingUrl).flashing(Success -> Messages("securesocial.email.verified"))
        case (Some(user), None) =>
          markAsActive(user)
          Redirect(RoutesHelper.login().url).flashing(Success -> Messages("securesocial.email.verified"))
        case _ =>
          Unauthorized("Not Authorized Page")
      }
    })
  }
}
