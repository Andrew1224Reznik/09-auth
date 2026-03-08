import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { parse } from "cookie";
import { checkSession } from "./lib/api/serverApi";

const privateRoure = ["/notes", "/profile"];
const publicRoute = ["/sign-in", "/sign-up"];

export async function proxy(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const cookie = await cookies();
  const accessToken = cookie.get("accessToken")?.value;
  const refreshToken = cookie.get("refreshToken")?.value;

  const isPublic = publicRoute.some((route) => path.startsWith(route));
  const isPrivate = privateRoure.some((route) => path.startsWith(route));

  if (accessToken) {
    if (isPrivate) {
      return NextResponse.next();
    }
    if (isPublic) {
      return NextResponse.redirect(new URL("/", req.url));
    }
  } else {
    if (refreshToken) {
      const data = await checkSession();
      const setCookie = data.headers["set-cookie"];

      if (setCookie) {
        const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const cookieStr of cookieArr) {
          const parsed = parse(cookieStr);
          const options = {
            expires: parsed.Expires ? new Date(parsed.Expires) : undefined,
            path: parsed.Path,
            maxAge: Number(parsed["Max-Age"]),
          };
          if (parsed.accessToken) {
            cookie.set("accessToken", parsed.accessToken, options);
          }
          if (parsed.refreshToken) {
            cookie.set("refreshToken", parsed.refreshToken, options);
          }
        }
        if (isPublic) {
          return NextResponse.redirect(new URL("/", req.url), {
            headers: {
              Cookie: cookie.toString(),
            },
          });
        }
        if (isPrivate) {
          return NextResponse.next({
            headers: {
              Cookie: cookie.toString(),
            },
          });
        }
      } else {
        if (isPublic) {
          return NextResponse.next();
        }
        if (isPrivate) {
          return NextResponse.redirect(new URL("/sign-in", req.url));
        }
      }
    } else {
      if (isPublic) {
        return NextResponse.next();
      }
      if (isPrivate) {
        return NextResponse.redirect(new URL("/sign-in", req.url));
      }
    }
  }
}

export const config = {
  matcher: ["/notes/:path*", "/profile/:path*", "/sign-up", "/sign-in"],
};
