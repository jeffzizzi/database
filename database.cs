using System;
using System.Text;
using System.Data;
using MySql.Data.MySqlClient;
using System.Data.Odbc;
using System.Data.SqlClient;
using System.Data.OleDb;
using System.Security.Cryptography;
using System.IO;
using System.Configuration;

namespace Database
{

    public class database
    {
        private static readonly log4net.ILog Log = log4net.LogManager.GetLogger(typeof(database));

        public static Random rdm = new Random();
        private static byte[] _salt = Encoding.ASCII.GetBytes("sLbQf6D-?Hu?dF{^");
        public string secret = "";

        private Object metricLock = new Object();
        /// <summary>
        /// Using an encrypted conn string? Good job.
        /// </summary>
        /// <param name="DecSecret">Your secret that you used to create the conn string.</param>
        public database(string DecSecret)
        {

            secret = DecSecret;

            var appSettings = ConfigurationManager.AppSettings;

            string key = ConfigurationManager.AppSettings["TMP"].ToString();
            Environment.SetEnvironmentVariable("TMP", key);
        }

        public string GetConnString(string input)
        {
            Log.Debug("In GetConnString...");
            string rtnval = "";
            try
            {
                rtnval = DecryptStringAES(input, secret);
            }
            catch (Exception e)
            {
                Log.ErrorFormat("Error in GetConnString: {0}", e);
            }
            return (rtnval);
        }

        /// <summary>
        /// Decrypt the given string.  Assumes the string was encrypted using 
        /// EncryptStringAES(), using an identical sharedSecret.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
        private string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create the streams used for decryption.                
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plaintext;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
        /* MySQL Stuff */
        public DataTable Exec_MySQL_SP_Get(string StoredProcedureName, string connectionString, params MySqlParameter[] SQLParams)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            DataTable returnVal = new DataTable();
            MySqlCommand command = new MySqlCommand();
            MySqlConnection conn = new MySqlConnection(connectionString);
            command.CommandType = CommandType.StoredProcedure;
            string addedParams = "";
            try
            {
                conn.Open();
                command.Connection = conn;
                command.CommandText = StoredProcedureName;
                if (SQLParams != null && SQLParams.Length > 0)
                {
                    foreach (MySqlParameter _param in SQLParams)
                    {
                        command.Parameters.Add(_param);
                        addedParams += _param.ParameterName + "|" + _param.Value.ToString();
                    }
                }
                MySqlDataAdapter da = new MySqlDataAdapter(command);
                da.Fill(returnVal);


            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to get table: " + err.ToString() +
                        " - Using SQL string: " + command.CommandText + ".");
            }
            finally
            {
                if (conn != null)
                    conn.Close();
            }
            if (returnVal.Rows.Count == 0)
                returnVal = null;
            end = DateTime.Now;
            ts = end - start;

            WriteMetrics(string.Format("\"{0} ({1})\",{2}", command.CommandText, addedParams, ts.TotalMilliseconds));
            return returnVal;
        }

        public int Exec_MySQL_SP_Update(string StoredProcedureName, string connectionString, params MySqlParameter[] SQLParams)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            int rtnVal = 0;
            MySqlCommand command = new MySqlCommand();
            MySqlConnection conn = new MySqlConnection(connectionString);
            command.CommandType = CommandType.StoredProcedure;
            string addedParams = "";
            try
            {
                conn.Open();
                command.Connection = conn;
                command.CommandText = StoredProcedureName;
                if (SQLParams != null && SQLParams.Length > 0)
                {
                    foreach (MySqlParameter _param in SQLParams)
                    {
                        command.Parameters.Add(_param);
                        addedParams += _param.ParameterName + "|" + _param.Value.ToString();
                    }
                }
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to get table: " + err.ToString() +
                        " - Using SQL string: " + command.CommandText + ".");
                rtnVal = -1;
            }
            finally
            {
                if (conn != null)
                    conn.Close();
            }
            end = DateTime.Now;
            ts = end - start;

            WriteMetrics(string.Format("\"{0} ({1})\",{2}", command.CommandText, addedParams, ts.TotalMilliseconds));
            return rtnVal;
        }




        /// <summary>
        /// Loads in data to a database
        /// </summary>
        /// <param name="DatabaseConnectionString">Connection String to database.</param>
        /// <param name="table">The schema and table the data will be loaded into.</param>
        /// <param name="ColumnList">Comma delimited list of column names to load data into.</param>
        /// <param name="dtData">Datatable of information (must match sequence of columnlist)</param>
        /// <param name="DeleteFiles">Whether to delete the temp load in file or not. True=Delete Files.</param>
        public int LoadData(string DatabaseConnectionString, string table,
            string ColumnList, DataTable dtData, bool DeleteFiles)
        {
            string tempFile = @"c:\temp\loadinfile_" + rdm.Next(10000000, 99999999).ToString() + ".csv";
            int rtnVal = 0;
            StringBuilder sb = new StringBuilder();
            foreach (DataRow row in dtData.Rows)
            {
                foreach (DataColumn col in row.Table.Columns)
                {
                    //if (col.ColumnName.ToUpper().Contains("DELETED"))
                    //    continue;
                    //A fix for boolean values to change them to integers.
                    if (col.DataType == typeof(Boolean))
                    {

                        bool tempVal = false;
                        bool.TryParse(row[col.ColumnName].ToString(), out tempVal);
                        if (tempVal == false)
                            sb.AppendFormat("\"{0}\"|", 0);
                        else
                            sb.AppendFormat("\"{0}\"|", 1);
                    }
                    else if (col.DataType == typeof(DateTime))
                    {
                        DateTime tempVal = new DateTime();
                        if (DateTime.TryParse(row[col.ColumnName].ToString(), out tempVal))
                        {
                            sb.AppendFormat("\"{0}\"|", tempVal.ToString("yyyy-MM-dd HH:mm:ss"));
                        }
                        else
                            sb.AppendFormat("\"{0}\"|", "2001-01-01 00:00:00");

                    }
                    else if (col.DataType == typeof(System.UInt64))
                    {
                        //This is a bit field and needs to be input as a b'<val>
                        if (row[col.ColumnName].ToString().Trim().Length == 1)
                        {
                            if (row[col.ColumnName].ToString().Trim() == "1")
                                sb.AppendFormat("\"{0}\"|", 1);
                            else
                            {
                                bool tempVal = false;
                                bool.TryParse(row[col.ColumnName].ToString(), out tempVal);
                                if (tempVal == false)
                                    sb.AppendFormat("\"\"|");
                                else
                                    sb.AppendFormat("\"{0}\"|", 1);
                            }

                        }
                        else
                            sb.AppendFormat("\"{0}\"|", row[col.ColumnName]);

                    }
                    else
                        sb.AppendFormat("\"{0}\"|", row[col.ColumnName]);
                }
                sb.Append("\n");
            }

            try
            {
                System.IO.File.WriteAllText(tempFile,
                    sb.ToString());
                //System.IO.File.Copy(tempFile, ServerTempDir + tempFile, true);
                //System.IO.File.SetAttributes(ServerTempDir + tempFile, System.IO.FileAttributes.Normal);

            }
            catch (Exception e)
            {
                WriteErrorLog("Unable to create file: " + e.ToString());
                rtnVal = -1;
                return rtnVal;
            }

            if (System.IO.File.Exists(tempFile))
            {
                try
                {
                    string insertCommand = @"LOAD DATA LOCAL INFILE '" + tempFile.Replace("\\", "\\\\") + "' " +
                        "INTO TABLE " + table + " " +
                        "FIELDS TERMINATED BY '|' ENCLOSED BY '\"' " +
                        "LINES TERMINATED BY '\n' " +
                        "(" + ColumnList + ");";
                    if (UpdateTableMySQL(insertCommand, DatabaseConnectionString) == 0)
                        rtnVal = 1;
                }
                catch (Exception err)
                {
                    WriteErrorLog("Unable to perform Load Infile: " + err.ToString());
                    rtnVal = -1;
                }
                finally
                {
                    if (DeleteFiles)
                    {
                        try
                        {
                            System.IO.File.Delete(tempFile);
                        }
                        catch (Exception e)
                        {
                            WriteErrorLog("Unable to delete files: " + e.ToString());
                        }
                    }
                }
                return rtnVal;
            }
            else return -1;
        }



        /// <summary>
        /// Creates a paramatized command for database updates.
        /// </summary>
        /// <param name="commandText">Command text. Any parameters passed much match the sequence in the command text.</param>
        /// <param name="ParameterValues">Objects used for populating the parameters of the command text. Must match the sequence in the command string.</param>
        /// <returns></returns>
        public MySqlCommand CreateMySQLCommand(string commandText, params object[] ParameterValues)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            MySqlCommand rtnVal = new MySqlCommand();
            //Assign the text
            rtnVal.CommandText = commandText;
            //Go through the commandtext and pull out the paramter names
            bool validParam = false;
            string paramName = "";
            string[] paramNameArray = new string[ParameterValues.Length];
            int paramArrayCount = 0;
            if (ParameterValues != null)
            {
                for (int x = 0; x < commandText.Length; x++)
                {
                    if (validParam)
                    {
                        //Check to see if we hit a space, the end of the text,
                        //a comma, or a ;.
                        if ("| |;|,|)|".Contains("|" + commandText.Substring(x, 1) + "|") == true ||
                            x == commandText.Length - 1)
                        {
                            //add the param to the array
                            paramNameArray[paramArrayCount] = paramName;
                            paramArrayCount++;
                            paramName = "";
                            validParam = false;
                        }
                        else
                            paramName += commandText.Substring(x, 1);
                    }
                    else
                    {
                        //check if this char is the "@" symbol
                        if (commandText.Substring(x, 1) == "@")
                        {
                            paramName = commandText.Substring(x, 1);
                            validParam = true;
                            continue;
                        }
                    }
                }

                //Check to see if the statement has IN statements as we will need to run things a bit different from here on out.
                if (commandText.ToUpper().Contains(" IN "))
                {
                    //We need to get the parameter names that this IN refers to
                    //Most of the time, there is only one IN statement and things get easy.
                    if (paramNameArray.Length == 1)
                    {
                        string valueStringBuild = "";
                        int valCount = 0;
                        ParameterValues = ParameterValues[0].ToString().Split(',');
                        foreach (string val in ParameterValues)
                        {
                            valueStringBuild += "@VAL" + valCount.ToString() + ",";
                            valCount++;
                        }
                        if (valueStringBuild.EndsWith(","))
                            valueStringBuild = valueStringBuild.Substring(0, valueStringBuild.Length - 1);

                        rtnVal.CommandText = rtnVal.CommandText.Replace(paramNameArray[0], valueStringBuild);

                        paramNameArray = valueStringBuild.Split(',');
                    }
                    else
                    {
                        //We have to find out which param name is associated with the IN keyword.
                        string testCommandText = rtnVal.CommandText.ToUpper();

                        int foundNdx = 0;

                        //Cut the string down until we don't find the IN keyword
                        foreach (string Name in paramNameArray)
                        {
                            if (testCommandText.Contains(Name.ToUpper()))
                            {
                                testCommandText = testCommandText.Substring(testCommandText.IndexOf(Name.ToUpper()), testCommandText.Length - testCommandText.IndexOf(Name.ToUpper()));

                                if (testCommandText.Contains(" IN "))
                                {
                                    testCommandText = testCommandText.Replace(Name, "");
                                    foundNdx++;
                                    continue;
                                }
                                else
                                {
                                    //We found the one with IN so foundNdx is the index of the param name that we will use.
                                    break;
                                }
                            }
                        }

                        string originalName = paramNameArray[foundNdx];

                        //Get the values that we will need to stuff in there.
                        string inVals = ParameterValues[foundNdx].ToString();
                        string[] inValsSplit = inVals.Split(',');
                        string valueStringBuild = "";
                        int valCount = 0;
                        foreach (string val in inValsSplit)
                        {
                            valueStringBuild += "@VAL" + valCount.ToString() + ",";
                            valCount++;
                        }
                        if (valueStringBuild.EndsWith(","))
                            valueStringBuild = valueStringBuild.Substring(0, valueStringBuild.Length - 1);

                        //Now that we have a string built to represent each value in the IN statement, we have to rebuild the paramNameArray and ParemeterValues array
                        //to insert the new fields.
                        Array.Resize(ref paramNameArray, paramNameArray.Length + inValsSplit.Length - 1);
                        Array.Resize(ref ParameterValues, ParameterValues.Length + inValsSplit.Length - 1);

                        //Now we need to insert in the new value names and new value starting at the index in which we found the item.
                        //If we find something in an index that is supposed to be blank, we will need to move it down

                        //Lets first work on the names.
                        int tempCount = 0;
                        string[] TempNameArray = valueStringBuild.Split(',');
                        for (int x = foundNdx; x < paramNameArray.Length; x++)
                        {

                            if (x == foundNdx)
                            {

                                //Replace that index value with the first value name

                                paramNameArray[x] = TempNameArray[tempCount];

                            }
                            else
                            {
                                if (paramNameArray[x] == null || paramNameArray[x].Length == 0)
                                {

                                    //If nothing was there, lets add in the next name
                                    paramNameArray[x] = TempNameArray[tempCount];


                                }
                                else
                                {
                                    //If we did find an existing value, move it to the next item.

                                    paramNameArray[x + 1] = paramNameArray[x];

                                    paramNameArray[x] = TempNameArray[tempCount];
                                }
                            }
                            tempCount++;
                        }
                        //Now on to the values
                        //Lets first work on the names.
                        tempCount = 0;
                        for (int x = foundNdx; x < ParameterValues.Length; x++)
                        {
                            if (x == foundNdx)
                            {
                                //Replace that index value with the first value name
                                ParameterValues[x] = inValsSplit[tempCount];
                            }
                            else
                            {
                                if (ParameterValues[x] == null || ParameterValues[x].ToString().Length == 0)
                                {
                                    //If nothing was there, lets add in the next name
                                    ParameterValues[x] = inValsSplit[tempCount];
                                }
                                else
                                {
                                    //If we did find an existing value, move it to the next item.
                                    ParameterValues[x + 1] = ParameterValues[x];
                                    ParameterValues[x] = inValsSplit[tempCount];
                                }
                            }
                            tempCount++;
                        }

                        //Now we need to restructure the commandtext with the new value names.
                        rtnVal.CommandText = rtnVal.CommandText.Replace(originalName, valueStringBuild);
                    }

                }




                //Now that we have the lists of names and values, add the params
                int count = 0;
                foreach (string Name in paramNameArray)
                {
                    rtnVal.Parameters.AddWithValue(Name, ParameterValues[count]);
                    count++;
                }
            }

            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", commandText, ts.TotalMilliseconds));
            return (rtnVal);
        }


        public OdbcCommand CreateODBCCommand(string commandText, params object[] ParameterValues)
        {
            OdbcCommand rtnVal = new OdbcCommand();
            //Assign the text
            rtnVal.CommandText = commandText;
            //Go through the commandtext and pull out the paramter names
            bool validParam = false;
            string paramName = "";
            string[] paramNameArray = new string[ParameterValues.Length];
            int paramArrayCount = 0;
            if (ParameterValues != null)
            {
                for (int x = 0; x < commandText.Length; x++)
                {
                    if (validParam)
                    {
                        //Check to see if we hit a space, the end of the text,
                        //a comma, or a ;.
                        if ("| |;|,|)|".Contains("|" + commandText.Substring(x, 1) + "|") == true ||
                            x == commandText.Length - 1)
                        {
                            //add the param to the array
                            paramNameArray[paramArrayCount] = paramName;
                            paramArrayCount++;
                            paramName = "";
                            validParam = false;
                        }
                        else
                            paramName += commandText.Substring(x, 1);
                    }
                    else
                    {
                        //check if this char is the "@" symbol
                        if (commandText.Substring(x, 1) == "@")
                        {
                            paramName = commandText.Substring(x, 1);
                            validParam = true;
                            continue;
                        }
                    }
                }
                //Now that we have the lists of names and values, add the params
                int count = 0;
                foreach (string Name in paramNameArray)
                {
                    rtnVal.Parameters.AddWithValue(Name, ParameterValues[count]);
                    count++;
                }
            }
            return (rtnVal);
        }


        public DataRow GetRowMySQL(string selectString, string MySqlConnectionString)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            DataRow drReturn = null;
            DataTable dtTemp = new DataTable();
            MySqlConnection connection = new MySqlConnection(MySqlConnectionString);
            MySqlDataAdapter adapter = new MySqlDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtTemp);
                if (dtTemp.Rows.Count > 0)
                    drReturn = dtTemp.Rows[0];
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datarow: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");



            }
            finally
            {
                connection.Close();
            }

            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", selectString, ts.TotalMilliseconds));
            return (drReturn);
        }

        public DataRow GetRowMySQL(MySqlCommand command, string MySqlConnectionString)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            DataRow drReturn = null;
            DataTable dtTemp = new DataTable();
            MySqlConnection connection = new MySqlConnection(MySqlConnectionString);
            command.Connection = connection;
            MySqlDataAdapter adapter = new MySqlDataAdapter(command);
            try
            {
                adapter.Fill(dtTemp);
                if (dtTemp.Rows.Count > 0)
                    drReturn = dtTemp.Rows[0];
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datarow: " + err.ToString() +
                    " - Using SQL string: " + command.CommandText + ".");



            }
            finally
            {
                connection.Close();
            }
            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", command.CommandText, ts.TotalMilliseconds));
            return (drReturn);
        }


        public DataTable GetTableMySQL(MySqlCommand command, string MySqlConnectionString)
        {
            lock (this)
            {
                DateTime start = DateTime.Now;
                DateTime end;
                TimeSpan ts;
                DataTable dtReturn = new DataTable();
                MySqlConnection conn = new MySqlConnection(MySqlConnectionString);
                try
                {
                    command.Connection = conn;
                    MySqlDataAdapter adapter = new MySqlDataAdapter(command);
                    adapter.Fill(dtReturn);
                }
                catch (Exception err)
                {
                    WriteErrorLog(">>Unable to return datatable: " + err.ToString() +
                        " - Using SQL string: " + command.CommandText + ".");



                }
                finally
                {
                    conn.Close();
                }
                if (dtReturn.Rows.Count == 0)
                    dtReturn = null;
                end = DateTime.Now;
                ts = end - start;
                WriteMetrics(string.Format("\"{0}\",{1}", command.CommandText, ts.TotalMilliseconds));
                return (dtReturn);
            }
        }


        public DataTable GetTableMySQL(string selectString, string MySqlConnectionString)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            DataTable dtReturn = new DataTable();
            MySqlConnection connection = new MySqlConnection(MySqlConnectionString);
            MySqlDataAdapter adapter = new MySqlDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtReturn);
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datatable: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");


            }
            finally
            {
                connection.Close();
            }
            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", selectString, ts.TotalMilliseconds));
            if (dtReturn.Rows.Count == 0)
                dtReturn = null;
            return (dtReturn);
        }

        public int UpdateTableMySQL(string updateString, string MySqlConnectionString)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            int returnValue = 0;
            MySqlConnection connection = new MySqlConnection(MySqlConnectionString);
            MySqlCommand command = new MySqlCommand(updateString, connection);
            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + updateString + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }

            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", updateString, ts.TotalMilliseconds));
            return (returnValue);
        }
        public int LoadDataSQL(string ConnString, string destinationTable, DataTable dtSource)
        {
            int returnVal = 0;
            using (SqlConnection destinationConnection =
                           new SqlConnection(ConnString))
            {
                destinationConnection.Open();

                // Set up the bulk copy object. 
                // Note that the column positions in the source
                // data reader match the column positions in 
                // the destination table so there is no need to
                // map columns.
                DateTime start = DateTime.Now;
                DateTime end;
                TimeSpan ts;
                using (SqlBulkCopy bulkCopy =
                           new SqlBulkCopy(destinationConnection))
                {
                    bulkCopy.DestinationTableName =
                        destinationTable;
                    bulkCopy.BulkCopyTimeout = 60;

                    try
                    {
                        bulkCopy.WriteToServer(dtSource);
                        returnVal = 1;
                    }
                    catch (Exception ex)
                    {
                        WriteErrorLog("Unable to LoadDataSQL: " + ex.ToString() +
                        " - Using destinationTable: " + destinationTable + ".");
                        returnVal = -1;
                    }
                    finally
                    {
                        destinationConnection.Close();
                    }

                }
                end = DateTime.Now;
                ts = end - start;
                WriteMetrics(string.Format("\"{0}\",{1}", "LoadDataSQL(string ConnString, string destinationTable, DataTable dtSource)", ts.TotalMilliseconds));
            }
            return returnVal;
        }
        private void WriteMetrics(string text)
        {
            lock (metricLock)
            {
                try
                {
                    string output = string.Format("{0},{1}{2}", DateTime.Now, text, Environment.NewLine);
                    //System.IO.File.AppendAllText(@"c:\logs\"+ MetricsLogFileName + "_" + DateTime.Now.ToString("yyyyMMdd") + ".log", output);
                }
                catch (Exception)
                {

                }

            }
        }
        public int UpdateTableMySQL(MySqlCommand command, string MySqlConnectionString)
        {
            DateTime start = DateTime.Now;
            DateTime end;
            TimeSpan ts;
            int returnValue = 0;
            MySqlConnection connection = new MySqlConnection(MySqlConnectionString);
            command.Connection = connection;

            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + command.CommandText + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }
            end = DateTime.Now;
            ts = end - start;
            WriteMetrics(string.Format("\"{0}\",{1}", command.CommandText, ts.TotalMilliseconds));
            return (returnValue);
        }
        /* ODBC Stuff */

        public DataRow GetRowODBC(string selectString, string ODBCconnectionString)
        {
            DataRow drReturn = null;
            DataTable dtTemp = new DataTable();
            OdbcConnection connection = new OdbcConnection(ODBCconnectionString);
            OdbcDataAdapter adapter = new OdbcDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtTemp);
                if (dtTemp.Rows.Count > 0)
                    drReturn = dtTemp.Rows[0];
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datarow: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");



            }
            finally
            {
                connection.Close();
            }
            return (drReturn);
        }

        public DataTable GetTableODBC(string selectString, string ODBCconnectionString)
        {
            DataTable dtReturn = new DataTable();
            OdbcConnection connection = new OdbcConnection(ODBCconnectionString);
            OdbcDataAdapter adapter = new OdbcDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtReturn);
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datatable: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");


            }
            finally
            {
                connection.Close();
            }

            if (dtReturn.Rows.Count == 0)
                dtReturn = null;
            return (dtReturn);
        }


        public int UpdateTableODBC(string updateString, string ODBCconnectionString)
        {
            int returnValue = 0;
            OdbcConnection connection = new OdbcConnection(ODBCconnectionString);
            OdbcCommand command = new OdbcCommand(updateString, connection);
            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + updateString + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }
            return (returnValue);
        }

        /* SQL Stuff */

        public DataRow GetRowSQL(string selectString, string SqlConnectionString)
        {
            DataRow drReturn = null;
            DataTable dtTemp = new DataTable();
            SqlConnection connection = new SqlConnection(SqlConnectionString);
            SqlDataAdapter adapter = new SqlDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtTemp);
                if (dtTemp.Rows.Count > 0)
                    drReturn = dtTemp.Rows[0];
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datarow: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");



            }
            finally
            {
                connection.Close();
            }
            return (drReturn);
        }


        public DataTable GetTableSQL(string selectString, string SqlConnectionString)
        {
            DataTable dtReturn = new DataTable();
            SqlConnection connection = new SqlConnection(SqlConnectionString);
            SqlDataAdapter adapter = new SqlDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtReturn);
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datatable: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");


            }
            finally
            {
                connection.Close();
            }
            if (dtReturn.Rows.Count == 0)
                dtReturn = null;
            return (dtReturn);
        }


        public int UpdateTableSQL(string updateString, string SqlConnectionString)
        {
            int returnValue = 0;
            SqlConnection connection = new SqlConnection(SqlConnectionString);
            SqlCommand command = new SqlCommand(updateString, connection);
            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + updateString + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }
            return (returnValue);
        }
        /* OleDB Stuff */
        public DataTable GetTableOleDb(OleDbCommand command, string OleDbconnectionString)
        {
            DataTable dtReturn = new DataTable();
            OleDbConnection connection = new OleDbConnection();
            try
            {
                using (connection = new OleDbConnection(OleDbconnectionString))
                {
                    command.Connection = connection;
                    OleDbDataAdapter adapter = new OleDbDataAdapter(command);
                }

            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datatable: " + err.ToString() +
                    " - Using SQL string: " + command.CommandText + ".");


            }
            finally
            {
                connection.Close();
            }
            if (dtReturn.Rows.Count == 0)
                dtReturn = null;
            return (dtReturn);
        }
        public int UpdateTableOleDb(OleDbCommand command, string OleDbconnectionString)
        {
            int returnValue = 0;
            OleDbConnection connection = new OleDbConnection(OleDbconnectionString);
            command.Connection = connection;
            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + command.CommandText + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }
            return (returnValue);
        }

        public DataRow GetRowOleDb(string selectString, string OleDbconnectionString)
        {
            DataRow drReturn = null;
            DataTable dtTemp = new DataTable();
            OleDbConnection connection = new OleDbConnection(OleDbconnectionString);
            OleDbDataAdapter adapter = new OleDbDataAdapter(selectString, connection);
            try
            {
                adapter.Fill(dtTemp);
                if (dtTemp.Rows.Count > 0)
                    drReturn = dtTemp.Rows[0];
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datarow: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");



            }
            finally
            {
                connection.Close();
            }
            return (drReturn);
        }

        public DataTable GetTableOleDb(string selectString, string OleDbconnectionString)
        {
            DataTable dtReturn = new DataTable();
            OleDbConnection connection = new OleDbConnection();
            try
            {
                using (connection = new OleDbConnection(OleDbconnectionString))
                {
                    OleDbDataAdapter adapter = new OleDbDataAdapter(selectString, connection);
                    adapter.Fill(dtReturn);
                }
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to return datatable: " + err.ToString() +
                    " - Using SQL string: " + selectString + ".");


            }
            finally
            {
                connection.Close();
            }
            if (dtReturn.Rows.Count == 0)
                dtReturn = null;
            return (dtReturn);
        }


        public int UpdateTableOleDb(string updateString, string OleDbconnectionString)
        {
            int returnValue = 0;
            OleDbConnection connection = new OleDbConnection(OleDbconnectionString);
            OleDbCommand command = new OleDbCommand(updateString, connection);
            try
            {
                connection.Open();
                command.ExecuteNonQuery();
            }
            catch (Exception err)
            {
                WriteErrorLog("Unable to update table: " + err.ToString() +
                    " - Using SQL string: " + updateString + ".");


                returnValue = -1;
            }
            finally
            {
                connection.Close();
            }
            return (returnValue);
        }

        public string GetStringFromAnObject(object AnObject)
        {
            string RtnVal = "";
            try
            {
                RtnVal = AnObject.ToString();
            }
            catch (Exception err)
            {
                WriteErrorLog("Error in GetStringFromAnObject: " + err.ToString());
            }

            return (RtnVal);
        }

        public int GetIntFromAnObject(object AnObject)
        {
            int RtnVal = 0;
            try
            {
                RtnVal = int.Parse(AnObject.ToString());
            }
            catch (Exception err)
            {
                WriteErrorLog("Error in GetIntFromAnObject: " + err.ToString());
            }
            return (RtnVal);
        }

        public bool GetBoolFromAnObject(object AnObject)
        {
            bool RtnVal = false;

            try
            {
                RtnVal = bool.Parse(AnObject.ToString());
            }
            catch (Exception)
            {
                //WriteErrorLog("Can't get bool from just AnObject, trying numerical," + err.ToString());
                try
                {
                    int val = GetIntFromAnObject(AnObject);
                    if (val == 1)
                        RtnVal = true;
                }
                catch (Exception err2)
                {
                    WriteErrorLog("Error in GetBoolFromAnObject: " + err2.ToString());
                }
            }

            return (RtnVal);
        }



        private void WriteErrorLog(string text)
        {
            lock (this)
            {
                string output = string.Format("{0}: {1}{2}",
                    DateTime.Now,
                    text,
                    System.Environment.NewLine);
                try
                {
                    Console.WriteLine(text);
                    Log.Error(text);
                }
                catch
                {
                    //Don't bother.
                }
            }
        }
    }
}

