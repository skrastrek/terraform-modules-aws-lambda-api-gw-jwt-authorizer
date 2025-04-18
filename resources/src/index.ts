import {JwtVerifier} from "aws-jwt-verify"
import {
    APIGatewayRequestAuthorizerWithContextHandler,
    APIGatewayRequestSimpleAuthorizerHandlerV2WithContext
} from "aws-lambda"
import {validateCognitoJwtFields} from "aws-jwt-verify/cognito-verifier"
import {
    CognitoIdentityProviderClient
} from "@aws-sdk/client-cognito-identity-provider"
import {AuthContextV1, AuthContextV2, TokenUse} from "./types";
import {getJwtSourcesFromEnv} from "./jwt/sources";
import {CognitoJwtEnricher} from "./jwt/enricher";
import {ApiGatewayV1JwtAuthorizer, ApiGatewayV2JwtAuthorizer} from "./jwt/authorizer";
import {JwtPayload} from "aws-jwt-verify/jwt-model";

const jwtSources = getJwtSourcesFromEnv()

const jwtVerifier = JwtVerifier.create([
    {
        issuer: process.env.JWT_ISSUER!!,
        audience: process.env.JWT_AUDIENCE?.split(",") ?? null,
        scope: process.env.JWT_SCOPE,
        customJwtCheck({payload}: { payload: JwtPayload }) {
            return validateCognitoJwtFields(
                payload,
                {
                    tokenUse: validateTokenUse(process.env.JWT_COGNITO_TOKEN_USE) ?? null,
                    clientId: process.env.JWT_COGNITO_CLIENT_ID?.split(",") ?? null,
                    groups: process.env.JWT_COGNITO_GROUP?.split(",") ?? null
                });
        },
    },
])

const cognitoJwtEnricher = new CognitoJwtEnricher(new CognitoIdentityProviderClient())

const apiGatewayV1JwtAuthorizer = new ApiGatewayV1JwtAuthorizer(jwtSources, jwtVerifier, cognitoJwtEnricher)
const apiGatewayV2JwtAuthorizer = new ApiGatewayV2JwtAuthorizer(jwtSources, jwtVerifier, cognitoJwtEnricher)

export const handlerV1: APIGatewayRequestAuthorizerWithContextHandler<AuthContextV1> = async event => {
    console.debug("Event:", JSON.stringify(event))
    let result = await apiGatewayV1JwtAuthorizer.authorize(event)
    console.debug("Result:", JSON.stringify(result))
    return result
}

export const handlerV2: APIGatewayRequestSimpleAuthorizerHandlerV2WithContext<AuthContextV2> = async event => {
    console.debug("Event:", JSON.stringify(event))
    let result = await apiGatewayV2JwtAuthorizer.authorize(event)
    console.debug("Result:", JSON.stringify(result))
    return result
}

function validateTokenUse(value?: string): TokenUse | undefined {
    if (value === undefined) {
        return undefined
    } else if (isTokenUse(value)) {
        return value
    } else {
        throw new Error(`Invalid token use: ${value}`)
    }
}

function isTokenUse(value: string): value is TokenUse {
    switch (value) {
        case "id":
        case "access":
            return true
        default:
            return false
    }
}
