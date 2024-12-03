import gql from 'graphql-tag';

export const RegisterQuery = gql`
    mutation Register($input: RegisterInput!) {
        register(data: $input) {
            user {
                id
                email
                name
                role
                avatar
                googleId
                isActivated
                isSuspended
            }
            accessToken
        }
    }
`;

export const LoginQuery = gql`
    query login($input: LoginInput!) {
        login(data: $input) {
            user {
                id
                email
                name
                role
                avatar
                googleId
                isActivated
                isSuspended
            }
            accessToken
        }
    }
`;

export const GoogleAuthQuery = gql`
    query GoogleAuth($data:SocialAuthInput!){
        googleAuth(data:$data) {
            accessToken
            user {
                id
                email
                name
                role
                avatar
                googleId
                isActivated
                isSuspended
            }
        }
    }
`;

export const GetGoogleAuthUrlQuery = gql`
    query {
        getGoogleAuthUrl
    }
`;

export const LogoutQuery = gql`
    query {
        logout{
            status
            message
        }
    }
`;

export const ForgotPasswordQuery = gql`
    query forgotPassword($input:String!){
        forgotPassword(email:$input){
            status
            message
        }
    }
`;

export const ResetPasswordQuery = gql`
    mutation resetPassword($input: ResetPwdInput!) {
        resetPassword(data:$input)
    }
`;

export const ActivateProfileQuery = gql`
    mutation activate($input: ActivateInput!) {
        activateProfile(data: $input)
    }
`;

export const ChangePasswordQuery = gql`
    mutation changePassword($data:ChangePwdInput!){
        changePassword(data: $data)
    }
`;

export const RefreshQuery = gql`
    query refresh {
        refresh {
            accessToken
        }
    }
`;

export const GetProfileQuery = gql`
    query Profile {
        user {
            id
            email
            name
            role
            avatar
            googleId
            isActivated
            isSuspended
        }
    }
`;

export const GetAllUsersQuery = gql`
    query {
        users {
            id
            email
            name
            role
            avatar
            googleId
            isActivated
            isSuspended
        }
    }
`;

export const GetUserQuery = gql`
    query GetUserProfile($input: String!) {
        getUser(id: $input) {
            id
            email
            name
            googleId
            role
            avatar
            isActivated
            isSuspended
            createdAt
            updatedAt
        }
    }
`;

export const UpdateProfileQuery = gql`
    mutation updateProfile($input: UpdateProfileInput!){
        updateProfile(data: $input) {
            id
            googleId
            name
            email
            avatar
            role
            isActivated
            isSuspended
            createdAt
            updatedAt
        }
    }
`;

export const UpdateUserProfileQuery = gql`
    mutation updateUserProfile($input: UpdateUserProfileInput!) {
        updateUserProfile(data: $input) {
            id
            googleId
            name
            email
            avatar
            role
            isActivated
            isSuspended
            createdAt
            updatedAt
        }
    }
`;