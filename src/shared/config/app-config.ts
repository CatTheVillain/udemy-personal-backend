export type ApplicationEnvironment = 'development' | 'production' | 'test';

const DEFAULT_PORT = 3000;
const LOCAL_ORIGIN_HOSTS = new Set(['localhost', '127.0.0.1']);

export class AppConfig {
  public readonly port: number;
  public readonly environment: ApplicationEnvironment;
  public readonly corsAllowedOrigins: readonly string[];

  private constructor(
    port: number,
    environment: ApplicationEnvironment,
    corsAllowedOrigins: readonly string[],
  ) {
    this.port = port;
    this.environment = environment;
    this.corsAllowedOrigins = corsAllowedOrigins;
  }

  public static from(environment: NodeJS.ProcessEnv): AppConfig {
    const applicationEnvironment = parseEnvironment(environment.NODE_ENV);
    const port = parsePort(environment.PORT);
    const corsAllowedOrigins = parseAllowedOrigins(
      environment.CORS_ALLOWED_ORIGINS,
      applicationEnvironment,
    );

    return new AppConfig(port, applicationEnvironment, corsAllowedOrigins);
  }
}

function parseEnvironment(value: string | undefined): ApplicationEnvironment {
  if (value === undefined || value === 'development') {
    return 'development';
  }

  if (value === 'production' || value === 'test') {
    return value;
  }

  throw new Error('Invalid application configuration.');
}

function parsePort(value: string | undefined): number {
  if (value === undefined) {
    return DEFAULT_PORT;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('Invalid application configuration.');
  }

  return port;
}

function parseAllowedOrigins(
  value: string | undefined,
  environment: ApplicationEnvironment,
): readonly string[] {
  const origins = value === undefined ? [] : value.split(',').map((origin) => origin.trim());

  if (origins.some((origin) => origin.length === 0)) {
    throw new Error('Invalid application configuration.');
  }

  if (environment === 'production' && origins.length === 0) {
    throw new Error('Invalid application configuration.');
  }

  origins.forEach((origin) => validateOrigin(origin, environment));
  return origins;
}

function validateOrigin(origin: string, environment: ApplicationEnvironment): void {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new Error('Invalid application configuration.');
  }

  if (url.origin !== origin) {
    throw new Error('Invalid application configuration.');
  }

  if (environment === 'production' && url.protocol !== 'https:') {
    throw new Error('Invalid application configuration.');
  }

  if (
    environment !== 'production' &&
    (url.protocol !== 'http:' || !LOCAL_ORIGIN_HOSTS.has(url.hostname))
  ) {
    throw new Error('Invalid application configuration.');
  }
}
