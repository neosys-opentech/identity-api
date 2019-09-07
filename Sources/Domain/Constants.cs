namespace Identity.Domain
{
    /// <summary>
    /// global constants class
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// dapper engine key for identity database
        /// </summary>
        public static string IdentityDb_ConnectionKey = "IdentityDb";

        /// <summary>
        /// name of AspNetRoles insert PS
        /// </summary>
        public static string PS_AspNetRoles_Insert = "ps_AspNetRoles_i";

        /// <summary>
        /// name of AspNetRoles delete PS
        /// </summary>
        public static string PS_AspNetRoles_Delete = "ps_AspNetRoles_d";

        /// <summary>
        /// name of AspNetRoles select by identifier PS
        /// </summary>
        public static string PS_AspNetRoles_SelectById = "ps_AspNetRoles_s_byId";

        /// <summary>
        /// name of AspNetRoles select by normalized name PS
        /// </summary>
        public static string PS_AspNetRoles_SelectByNormalizedName = "ps_AspNetRoles_s_byNormalizedName";

        /// <summary>
        /// name of AspNetRoles update PS
        /// </summary>
        public static string PS_AspNetRoles_Update = "ps_AspNetRoles_u";

        /// <summary>
        /// name of AspNetUsers select by noramlized email PS
        /// </summary>
        public static string PS_AspNetUsers_SelectByNormalizedEmail = "ps_AspNetUsers_s_byNormalizedEmail";

        /// <summary>
        /// name of AspNetUserRoles insert PS
        /// </summary>
        public static string PS_AspNetUserRoles_Insert = "ps_AspNetUserRoles_i";

        /// <summary>
        /// select roles based on user id PS
        /// </summary>
        public static string PS_AspNetRoles_SelectByUserId = "ps_AspNetRoles_s_byUserId";

        /// <summary>
        /// select users affected to a role by role id PS
        /// </summary>
        public static string PS_AspNetUsers_SelectByRoleId = "ps_AspNetUsers_s_byRoleId";

        /// <summary>
        /// select user role by role id and user id PS name
        /// </summary>
        public static string PS_AspNetUserRoles_SelectByRoleIdAndUserId = "ps_AspNetUserRoles_s_byRoleIdUserId";

        /// <summary>
        /// delete user role PS name
        /// </summary>
        public static string PS_AspNetUserRoles_Delete = "ps_AspNetUserRoles_d";

        /// <summary>
        /// create new users PS name
        /// </summary>
        public static string PS_AspNetUsers_Insert = "ps_AspNetUsers_i";

        /// <summary>
        /// delete existing user PS name
        /// </summary>
        public static string PS_AspNetUsers_Delete = "ps_AspNetUsers_d";

        /// <summary>
        /// select users by identifiers PS name
        /// </summary>
        public static string PS_AspNetUsers_SelectById = "ps_AspNetUsers_s_byId";

        /// <summary>
        /// update users PS name
        /// </summary>
        public static string PS_AspNetUsers_Update = "ps_AspNetUsers_u";

        /// <summary>
        /// name of AspNetRoles select all PS
        /// </summary>
        public static string PS_AspNetRoles_SelectAll = "ps_AspNetRoles_s";

        /// <summary>
        /// name of AspNetUsers select all PS
        /// </summary>
        public static string PS_AspNetUsers_SelectAll = "ps_AspNetUsers_s";
    }
}
