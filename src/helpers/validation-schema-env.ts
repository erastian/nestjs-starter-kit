import { Logger } from '@nestjs/common';
import Ajv from 'ajv';

const ajv = new Ajv({ allErrors: true, useDefaults: true });

const schema = {
  type: 'object',
  properties: {
    PRISMA_HOST: { type: 'string' },
    PRISMA_PORT: { type: 'string' },
    PRISMA_USER: { type: 'string' },
    PRISMA_PASSWORD: { type: 'string' },
    PRISMA_DATABASE: { type: 'string' },
  },
  required: [
    'PRISMA_HOST',
    'PRISMA_PORT',
    'PRISMA_USER',
    'PRISMA_PASSWORD',
    'PRISMA_DATABASE',
  ],
};

const validate = ajv.compile(schema);

export const validateSchemeEnv = (
  env: Record<string, string>,
): Record<string, string> => {
  const valid = validate(env);
  if (!valid) {
    const errorMessages = validate.errors
      .map((err) => ` Property ${err.instancePath} ${err.message}`)
      .join(', ');
    Logger.error(
      `Environment validation failed: ${errorMessages}`,
      'EnvValidation',
    );
  }
  return env;
};
