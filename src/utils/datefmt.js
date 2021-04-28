const datefmt = (date, options) =>
  new Date(date).toLocaleDateString(undefined, { timeZone: 'UTC', ...options })

export default datefmt
