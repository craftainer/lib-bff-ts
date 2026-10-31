import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeBff, type TestBff } from "./helpers/bff.ts";
import { PUBLIC_ORIGIN, startIdp, type TestIdp } from "./helpers/idp.ts";

let idp: TestIdp;
let bff: TestBff;

beforeAll(async () => {
  idp = await startIdp();
  bff = await makeBff(idp);
});

afterAll(async () => {
  await bff.app.close();
  await idp.close();
});

describe("smoke", () => {
  it("logs in", async () => {
    const cb = await bff.browser.login("/dashboard?x=1");
    console.log(cb.statusCode, cb.headers["location"], cb.setCookies, bff.logs.slice(-3));
    expect(cb.statusCode).toBe(302);
    const user = await bff.browser.request("GET", "/bff/user");
    console.log(user.body);
    expect(PUBLIC_ORIGIN).toBeTruthy();
  });
});
