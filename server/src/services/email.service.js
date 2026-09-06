// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import logger from '../utils/logger.js';

const defaultFrom = () => process.env.EMAIL_FROM || `Vault <${process.env.EMAIL_FROM_ADDRESS || 'onboarding@resend.dev'}>`;

let resendClient = null;

async function getResendClient() {
  const { RESEND_API_KEY } = process.env;
  if (!RESEND_API_KEY) return null;
  if (resendClient) return resendClient;
  const { Resend } = await import('resend');
  resendClient = new Resend(RESEND_API_KEY);
  return resendClient;
}

export async function sendEmail(to, subject, body) {
  const from = defaultFrom();
  const client = await getResendClient();

  if (!client) {
    if (process.env.NODE_ENV === 'production') {
      logger.info({ emailTo: to, subject }, '[EMAIL STUB] Email delivery not configured for production. Set RESEND_API_KEY.');
      return { delivered: false, stubbed: true };
    }
    logger.info({ emailTo: to, subject }, `[EMAIL STUB] ${body}`);
    return { delivered: false, stubbed: true };
  }

  try {
    const { error } = await client.emails.send({
      from,
      to,
      subject,
      text: body,
    });
    if (error) throw new Error(typeof error === 'string' ? error : error.message);
    logger.info({ emailTo: to, subject }, 'Email sent via Resend');
    return { delivered: true, stubbed: false };
  } catch (err) {
    logger.error({ err: err.message, emailTo: to, subject }, 'Failed to send email via Resend');
    throw err;
  }
}