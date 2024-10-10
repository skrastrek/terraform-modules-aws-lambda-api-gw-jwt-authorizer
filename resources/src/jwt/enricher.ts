import {JwtPayload} from "aws-jwt-verify/jwt-model";
import {
    CognitoIdentityProviderClient,
    GetUserCommand,
    GetUserCommandOutput,
    NotAuthorizedException,
    PasswordResetRequiredException,
    UserNotConfirmedException,
    UserNotFoundException
} from "@aws-sdk/client-cognito-identity-provider";
import {UserAttributes} from "../types";

export interface JwtEnricher<E> {
    enrich(jwt: string, jwtPayload: JwtPayload): Promise<E | undefined>
}

export class CognitoJwtEnricher implements JwtEnricher<UserAttributes> {

    constructor(private cognitoClient: CognitoIdentityProviderClient) {
    }

    enrich = async (jwt: string, jwtPayload: JwtPayload): Promise<UserAttributes | undefined> => {
        if (canContextBeEnrichedWithAwsCognitoUserAttributes(jwtPayload)) {
            return userAttributes(await this.getUserData(jwt))
        }
    };

    getUserData = async (accessToken: string): Promise<GetUserCommandOutput> => {
        try {
            return await this.cognitoClient.send(
                new GetUserCommand({
                    AccessToken: accessToken
                })
            );
        } catch (error) {
            console.error("Could not get user data:", error.message)
            switch (error.constructor) {
                case NotAuthorizedException:
                case PasswordResetRequiredException:
                case UserNotConfirmedException:
                case UserNotFoundException:
                    throw new Error("Unauthorized")
                default:
                    throw error
            }
        }
    };
}

function canContextBeEnrichedWithAwsCognitoUserAttributes(jwt: JwtPayload): boolean {
    return isAccessToken(jwt)
        && hasAwsCognitoUserAdminScope(jwt.scope)
        && isIssuedByAwsCognito(jwt.iss)
}

function isAccessToken(jwt: JwtPayload): boolean {
    return jwt.token_use === "access"
}

function hasAwsCognitoUserAdminScope(scope?: string): boolean {
    return scope?.includes("aws.cognito.signin.user.admin") ?? false
}

function isIssuedByAwsCognito(iss?: string): boolean {
    return iss !== undefined && iss.startsWith("https://cognito-idp.") && iss.includes("amazonaws.com")
}

function userAttributes(userData: GetUserCommandOutput): UserAttributes {
    return userData.UserAttributes?.reduce((result, curr) => ({...result, [curr.Name!!]: curr.Value}), {}) ?? {}
}
