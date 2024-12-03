import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import Capitalize from '../../helpers/capitalizer';

interface IMailData {
  email: string;
  name?: string;
  googleId?: string;
  token?: string;
}

interface IMailOptions {
  email: string;
  name?: string;
  template: string;
  subject: string;
  link?: string;
}

@Injectable()
export class MailerTransportService {
  constructor(
    private configService: ConfigService,
    private readonly mailerService: MailerService,
  ) {
  }

  private mailOptions(payload: IMailOptions) {
    return {
      from: `${ this.configService.get('SERVER_NAME') } Admin <${ this.configService.get('MAILER_USER') }>`,
      to: `${ payload.name ? Capitalize(payload.name) : 'New user' } <${ payload.email }>`,
      subject: payload.subject,
      template: payload.template,
      context: {
        serverName: this.configService.get('SERVER_NAME'),
        frontendUrl: this.configService.get('FRONTEND_URL'),
        username: payload.name ? Capitalize(payload.name) : 'user',
        link: payload.link ? payload.link : ''
      }
    }
  }

  async sendRegistrationEmail(payload: IMailData): Promise<void> {
    const mailData = {
      ...payload,
      template: payload.googleId ? 'google-registration' : 'registration',
      subject: `Welcome to a ${ this.configService.get('SERVER_NAME') } site, ${ payload.name ? Capitalize(payload.name) : 'user' }!`,
      link: `${ this.configService.get('FRONTEND_URL') }/activate/?token=${ payload.token }`
    };

    return this.sendEmail(this.mailOptions(mailData));
  }

  async SendPasswordRestorationEmail(payload: IMailData): Promise<void> {
    const mailData = {
      ...payload,
      template: 'reset-password',
      subject: `Password reset request for ${ this.configService.get('SERVER_NAME') } site, ${ payload.name ? Capitalize(payload.name) : 'user' }!`,
      link: `${ this.configService.get('FRONTEND_URL') }/reset-pwd/?token=${ payload.token }`
    };

    return this.sendEmail(this.mailOptions(mailData));
  }

  private sendEmail(payload): void {
    this.mailerService.sendMail(payload).catch((e) => {
      Logger.error('Error sending email', 'MailerService', e);
      throw new InternalServerErrorException('Something went wrong. Please try again later.');
    })
  }
}