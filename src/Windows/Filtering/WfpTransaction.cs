namespace IPGuard.Windows.Filtering;

/// <summary>Preserves an operation failure together with any failed rollback.</summary>
internal static class WfpTransaction
{
    /// <summary>Executes an action in an explicit transaction and aborts after any operation failure.</summary>
    internal static void Run(IWfpSession session, bool readOnly, Action action)
    {
        session.BeginTransaction(readOnly);
        try
        {
            action();
            session.CommitTransaction();
        }
        catch (Exception operationError)
        {
            try
            {
                session.AbortTransaction();
            }
            catch (Exception rollbackError)
            {
                throw new AggregateException("The WFP operation and its rollback failed.", operationError, rollbackError);
            }

            throw;
        }
    }
}
