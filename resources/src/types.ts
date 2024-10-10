import {Json} from "aws-jwt-verify/safe-json-parse";

export type AuthContextV1 = { [key: string]: Primitive }
export type AuthContextV2 = { [key: string]: boolean | number | string | string[] | Json }

export type Primitive = boolean | number | string
export type PrimitiveValues = { [key: string]: Primitive }

export interface RequestCookie {
    name: string,
    value: string
}

export type TokenUse = "id" | "access"

export type UserAttributes = { [key: string]: string }
