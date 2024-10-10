import {APIGatewayRequestAuthorizerEvent, APIGatewayRequestAuthorizerEventV2} from "aws-lambda"
import {APIGatewayRequestAuthorizerEventHeaders} from "aws-lambda/trigger/api-gateway-authorizer"
import {RequestCookie} from "../types";

type AnyObject<T> = { [key: string]: T | undefined };

const COOKIE_HEADER: string = "cookie"

export interface JwtExtractor<E> {
    extract(event: E): string | undefined
}

abstract class ChainedJwtExtractor<E> implements JwtExtractor<E> {
    protected constructor(private readonly extractors: JwtExtractor<E>[]) {
    }

    extract(event: E): string | undefined {
        return this.extractors.map(extractor => extractor.extract(event)).find(jwt => jwt !== undefined)
    }
}

export class AuthorizerEventV1JwtExtractor extends ChainedJwtExtractor<APIGatewayRequestAuthorizerEvent> {
    constructor(headerName: string, cookieRegex: RegExp) {
        super([new AuthorizerEventV1HeaderJwtExtractor(headerName), new AuthorizerEventV1CookieJwtExtractor(cookieRegex)])
    }
}

export class AuthorizerEventV2JwtExtractor extends ChainedJwtExtractor<APIGatewayRequestAuthorizerEventV2> {
    constructor(headerName: string, cookieRegex: RegExp) {
        super([new AuthorizerEventV2HeaderJwtExtractor(headerName), new AuthorizerEventV2CookieJwtExtractor(cookieRegex)])
    }
}

export class AuthorizerEventV1NoOpJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEvent> {
    extract(event: APIGatewayRequestAuthorizerEvent): string | undefined {
        return undefined
    }
}

export class AuthorizerEventV2NoOpJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEventV2> {
    extract(event: APIGatewayRequestAuthorizerEventV2): string | undefined {
        return undefined
    }
}

export class AuthorizerEventV1HeaderJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEvent> {

    constructor(private readonly headerName: string) {
    }

    extract(event: APIGatewayRequestAuthorizerEvent): string | undefined {

        const jwtFromHeader = extractJwtFromHeaders(event.headers ?? {}, this.headerName)

        if (jwtFromHeader !== undefined) {
            console.debug(`Found JWT from header: ${this.headerName}.`)
            return jwtFromHeader
        }

        console.debug(`Could not find JWT from header: ${this.headerName}.`)
        return undefined
    }
}

export class AuthorizerEventV1CookieJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEvent> {

    constructor(private readonly cookieRegex: RegExp) {
    }

    extract(event: APIGatewayRequestAuthorizerEvent): string | undefined {

        const cookies: string[] = findValueIgnoreCase(event.headers ?? {}, COOKIE_HEADER)?.split("; ") ?? []
        const jwtFromCookie = findFirstCookieMatching(cookies, this.cookieRegex)

        if (jwtFromCookie !== undefined) {
            console.debug(`Found JWT from cookie: ${this.cookieRegex.source}.`)
            return jwtFromCookie.value
        }

        console.debug(`Could not find JWT from cookie: ${this.cookieRegex.source}`)
        return undefined
    }
}

export class AuthorizerEventV2HeaderJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEventV2> {

    constructor(private readonly headerName: string) {
    }

    extract(event: APIGatewayRequestAuthorizerEventV2): string | undefined {

        const jwtFromHeader = extractJwtFromHeaders(event.headers ?? {}, this.headerName)

        if (jwtFromHeader !== undefined) {
            console.debug(`Found JWT from header: ${this.headerName}.`)
            return jwtFromHeader
        }

        console.debug(`Could not find JWT from header: ${this.headerName}.`)
        return undefined
    }
}

export class AuthorizerEventV2CookieJwtExtractor implements JwtExtractor<APIGatewayRequestAuthorizerEventV2> {

    constructor(private readonly cookieRegex: RegExp) {
    }

    extract(event: APIGatewayRequestAuthorizerEventV2): string | undefined {

        const jwtFromCookie = findFirstCookieMatching(event.cookies ?? [], this.cookieRegex)

        if (jwtFromCookie !== undefined) {
            console.debug(`Found JWT from cookie: ${jwtFromCookie.name}.`)
            return jwtFromCookie.value
        }

        console.debug(`Could not find JWT from cookie: ${this.cookieRegex.source}`)
        return undefined
    }
}

const extractJwtFromHeaders = (headers: APIGatewayRequestAuthorizerEventHeaders, jwtHeaderName: string): string | undefined =>
    findValueIgnoreCase(headers, jwtHeaderName)?.replace("Bearer ", "")

const findFirstCookieMatching = (cookies: string[], cookieRegex: RegExp): RequestCookie | undefined =>
    cookies
        .map(value => {
            const split = value.split("=")
            return {
                name: split[0],
                value: split[1]
            }
        })
        .find(cookie => cookieRegex.test(cookie.name))

const findValueIgnoreCase = <T>(object: AnyObject<T>, key: string): T | undefined => {
    const keyIgnoreCase = findKeyIgnoreCase(object, key)

    return keyIgnoreCase !== undefined ? object[keyIgnoreCase] : undefined;
};

const findKeyIgnoreCase = (object: any, key: string): string | undefined =>
    Object.keys(object).find(k => k.toLowerCase() === key.toLowerCase());
