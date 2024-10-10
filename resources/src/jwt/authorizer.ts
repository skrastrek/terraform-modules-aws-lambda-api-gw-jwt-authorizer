import {JwtRsaVerifier} from "aws-jwt-verify/jwt-rsa";
import {JwtPayload} from "aws-jwt-verify/jwt-model";
import {
    APIGatewayAuthorizerWithContextResult,
    APIGatewayRequestAuthorizerEvent,
    APIGatewayRequestAuthorizerEventV2
} from "aws-lambda";
import {APIGatewaySimpleAuthorizerWithContextResult} from "aws-lambda/trigger/api-gateway-authorizer";
import {AuthContextV1, AuthContextV2, Primitive, PrimitiveValues, UserAttributes} from "../types";
import {JwtEnricher} from "./enricher";
import {JwtExtractor} from "./extractor";
import {JwtSources} from "./sources";

export abstract class JwtAuthorizer<E, R, Attributes> {

    protected constructor(
        private readonly extractor: JwtExtractor<E>,
        private readonly verifier: JwtRsaVerifier<any, any, any>,
        private readonly enricher: JwtEnricher<Attributes>,
    ) {
    }

    abstract result: (event: E, verifiedJwt: (JwtPayload), attributes?: Attributes) => R;

    authorize = async (event: E): Promise<R> => {
        const jwt = this.extractor.extract(event)

        if (jwt === undefined) {
            console.warn("Could not find any JWT.")
            throw new Error("Unauthorized")
        }

        let verifiedJwtPayload: JwtPayload
        try {
            // If the token is not valid, an error is thrown:
            verifiedJwtPayload = await this.verifier.verify(jwt)
        } catch (error) {
            console.error("Invalid JWT:", error.message)
            throw new Error("Unauthorized")
        }

        return this.result(event, verifiedJwtPayload, await this.enricher.enrich(jwt, verifiedJwtPayload))
    };
}

export class ApiGatewayV1JwtAuthorizer extends JwtAuthorizer<APIGatewayRequestAuthorizerEvent, APIGatewayAuthorizerWithContextResult<AuthContextV1>, UserAttributes> {
    constructor(
        jwtSources: JwtSources,
        jwtVerifier: JwtRsaVerifier<any, any, any>,
        jwtEnricher: JwtEnricher<UserAttributes>,
    ) {
        super(jwtSources.v1JwtExtractor(), jwtVerifier, jwtEnricher);
    }

    result = (event: APIGatewayRequestAuthorizerEvent, verifiedJwt: JwtPayload, attributes?: UserAttributes): APIGatewayAuthorizerWithContextResult<AuthContextV1> => ({
        principalId: verifiedJwt.sub!!,
        policyDocument: {
            Version: "2012-10-17",
            Statement: [
                {
                    Action: "execute-api:Invoke",
                    Effect: "Allow",
                    Resource: event.methodArn
                }
            ]
        },
        context: {
            ...primitiveValues(verifiedJwt),
            ...attributes,
        },
        usageIdentifierKey: verifiedJwt.sub
    });
}

export class ApiGatewayV2JwtAuthorizer extends JwtAuthorizer<APIGatewayRequestAuthorizerEventV2, APIGatewaySimpleAuthorizerWithContextResult<AuthContextV2>, UserAttributes> {
    constructor(
        jwtSources: JwtSources,
        jwtVerifier: JwtRsaVerifier<any, any, any>,
        jwtEnricher: JwtEnricher<UserAttributes>,
    ) {
        super(jwtSources.v2JwtExtractor(), jwtVerifier, jwtEnricher);
    }

    result = (event: APIGatewayRequestAuthorizerEventV2, verifiedJwt: JwtPayload, attributes?: UserAttributes): APIGatewaySimpleAuthorizerWithContextResult<AuthContextV2> => ({
        isAuthorized: true,
        context: {
            ...verifiedJwt,
            ...attributes
        }
    });
}

function primitiveValues(object: any): PrimitiveValues {
    return Object.entries(object)
        .filter<[string, Primitive]>((entry): entry is [string, Primitive] => isPrimitive(entry[1]))
        .reduce((result, curr) => ({...result, [curr[0]]: curr[1]}), {})
}

function isPrimitive(value?: any): value is Primitive {
    switch (typeof value) {
        case "boolean":
        case "string":
        case "number":
            return true

        default:
            return false
    }
}
