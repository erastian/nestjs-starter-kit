export interface RegisterDto {
    email: string;
    password: string;
    name?: string;
    avatar?: string;
    googleId?: string | null;
}