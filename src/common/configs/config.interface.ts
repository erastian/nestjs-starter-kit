export interface Config {
  envFilePath: string[];
  validate: (env: Record<string, string>) => Record<string, string>;
  nest: NestConfig;
  cors: CorsConfig;
  swagger: SwaggerConfig;
  graphql: GraphQLConfig;
  security: SecurityConfig;
  mailer: MailerConfig;
}

export interface NestConfig {
  port: number;
}

export interface CorsConfig {
  enabled: boolean;
  frontendUrl: string;
  methods: string;
}

export interface SwaggerConfig {
  enabled: boolean;
  title: string;
  description: string;
  version: string;
  path: string;
}

export interface GraphQLConfig {
  playgroundEnabled: boolean;
  debug: boolean;
  schemaDestination: string;
  sortSchema: boolean;
}

export interface SecurityConfig {
  jwtAccessSecret: string;
  jwtAccessExpiresIn: string;
  jwtRefreshSecret: string;
  jwtRefreshExpiresIn: string;
  saltOrRounds: number;
  jwtResetSecret: string;
  jwtResetExpiresIn: string;
  jwtActivationTokenSecret: string;
  jwtActivationTokenExpiresIn: string;
}

export interface MailerConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  debug: boolean;
  logger: boolean;
}
