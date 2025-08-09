import { PrismaClient } from "@prisma/client";

declare global {
  var prisma: PrismaClient;
}

// biome-ignore lint/suspicious/noRedeclare: not sure why it needs to be global? (@vitalyso)
const prisma = global.prisma || new PrismaClient();

if (process.env.NODE_ENV !== "production") global.prisma = prisma;

export default prisma;