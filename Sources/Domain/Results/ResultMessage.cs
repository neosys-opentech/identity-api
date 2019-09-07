using System.Collections.Generic;

namespace Identity.Domain.Results
{
    /// <summary>
    /// api result class
    /// </summary>
    public class ResultMessage
    {
        /// <summary>
        /// gets or sets the operation status
        /// </summary>
        public bool OperationStatus { get; set; }

        /// <summary>
        /// gets or sets error messages list
        /// </summary>
        public IEnumerable<string> ErrorMessages { get; set; }
    }
}
