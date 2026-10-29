declare module "*.cjs" {
  const create: (options?: Record<string, unknown>) => Promise<import("./unicorn-types.ts").UnicornModule>;
  export default create;
}
