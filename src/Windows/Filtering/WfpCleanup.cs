namespace IPGuard.Windows.Filtering;

/// <summary>Runs required cleanup while retaining both operation and cleanup failures.</summary>
internal static class WfpCleanup
{
    /// <summary>Attempts cleanup exactly once, including when the operation fails.</summary>
    internal static void Run(Action operation, Action cleanup)
    {
        try
        {
            operation();
        }
        catch (Exception operationError)
        {
            try
            {
                cleanup();
            }
            catch (Exception cleanupError)
            {
                throw new AggregateException("The WFP operation and its cleanup failed.", operationError, cleanupError);
            }

            throw;
        }

        cleanup();
    }
}
