import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { PrismaService } from 'nestjs-prisma';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
let prismaService: PrismaService;

async function setupTestContainer() {
  const container = await new PostgreSqlContainer('postgres').start();

  return {
    host: container.getHost(),
    port: container.getMappedPort(5432),
    database: container.getDatabase(),
    user: container.getUsername(),
    password: container.getPassword(),
  };
}

beforeAll(async ()=> {
  const connectionConfig = await setupTestContainer();

  const databaseUrl = `postgresql://${ connectionConfig.user }:${ connectionConfig.password }@${ connectionConfig.host }:${ connectionConfig.port }/${ connectionConfig.database }`;

  const result = await execAsync(`DATABASE_URL=${ databaseUrl } npx prisma db push`);

  prismaService = new PrismaService({
    prismaOptions: {
      datasourceUrl: databaseUrl,
    }
  });
})

afterAll(async () => {
  await prismaService.$disconnect();
})

jest.setTimeout(15000);

export { prismaService };