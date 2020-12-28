/** @jsx jsx */
import { Grid, jsx } from 'theme-ui'
import { Fragment, useRef, useState } from 'react'
import Fuse from 'fuse.js'

import SearchBar from './searchbar'
import debounce from '../utils/debounce'

const CardGrid = ({ items, Card, fuseOptions, ...props }) => {
  const [pattern, setPattern] = useState('')
  const [displayedItems, setDisplayedItems] = useState(items)

  const fuse = useRef(new Fuse(items, fuseOptions)).current

  const search = useRef(debounce((value) => {
    const res = (value === '')
      ? items
      : fuse.search(value).map(val => val.item)
      // potential performance gain from using refIndex instead
      // and just showing/hiding cards
    setDisplayedItems(res)
  }, 100)).current

  const onSearchAction = useRef((e) => {
    setPattern(e.target.value)
    search(e.target.value)
  }).current

  return (
    <Fragment>
      <SearchBar onChange={onSearchAction} value={pattern} />
      <Grid
        {...props}
        sx={{
          gridTemplateColumns: [
            'repeat(auto-fill, minmax(250px, 1fr))',  // better way to do this?
            null,
            'repeat(auto-fill, minmax(300px, 1fr))',
          ],
        }}
      >
        {displayedItems.map((obj, i) => <Card key={i} {...obj}></Card>)}
      </Grid>
    </Fragment>
  )
}

export default CardGrid
