import {
    AuthorizerEventV1CookieJwtExtractor,
    AuthorizerEventV1HeaderJwtExtractor,
    AuthorizerEventV1JwtExtractor,
    AuthorizerEventV1NoOpJwtExtractor,
    AuthorizerEventV2CookieJwtExtractor,
    AuthorizerEventV2HeaderJwtExtractor,
    AuthorizerEventV2JwtExtractor, AuthorizerEventV2NoOpJwtExtractor,
    JwtExtractor
} from "./extractor";
import {APIGatewayRequestAuthorizerEvent, APIGatewayRequestAuthorizerEventV2} from "aws-lambda";

export class JwtSources {
    constructor(
        private readonly headerName: string | undefined,
        private readonly cookieRegex: RegExp | undefined
    ) {
    }

    v1JwtExtractor(): JwtExtractor<APIGatewayRequestAuthorizerEvent> {
        if (this.headerName !== undefined && this.cookieRegex !== undefined) {
            return new AuthorizerEventV1JwtExtractor(this.headerName, this.cookieRegex)
        } else if (this.headerName !== undefined && this.cookieRegex === undefined) {
            return new AuthorizerEventV1HeaderJwtExtractor(this.headerName)
        } else if (this.cookieRegex !== undefined && this.headerName === undefined) {
            return new AuthorizerEventV1CookieJwtExtractor(this.cookieRegex)
        } else {
            return new AuthorizerEventV1NoOpJwtExtractor()
        }
    }

    v2JwtExtractor(): JwtExtractor<APIGatewayRequestAuthorizerEventV2> {
        if (this.headerName !== undefined && this.cookieRegex !== undefined) {
            return new AuthorizerEventV2JwtExtractor(this.headerName, this.cookieRegex)
        } else if (this.headerName !== undefined && this.cookieRegex === undefined) {
            return new AuthorizerEventV2HeaderJwtExtractor(this.headerName)
        } else if (this.cookieRegex !== undefined && this.headerName === undefined) {
            return new AuthorizerEventV2CookieJwtExtractor(this.cookieRegex)
        } else {
            return new AuthorizerEventV2NoOpJwtExtractor()
        }
    }
}

export const getJwtSourcesFromEnv = (): JwtSources => new JwtSources(
    process.env.JWT_SOURCE_HEADER_NAME,
    process.env.JWT_SOURCE_COOKIE_REGEX ? RegExp(process.env.JWT_SOURCE_COOKIE_REGEX) : undefined
)
