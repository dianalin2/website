/** @jsx jsx */
import { Grid, jsx } from 'theme-ui'
import { useRef, useState } from 'react'
import Fuse from 'fuse.js'

import SearchBar from './searchbar'
import debounce from '../utils/debounce'
import { motion } from 'framer-motion'
import { fadeInUp } from '../animations/animations'

const CardGrid = ({ items, Card, fuseOptions, ...props }) => {
  const [pattern, setPattern] = useState('')
  const [displayedItems, setDisplayedItems] = useState(items)

  const fuse = useRef(new Fuse(items, fuseOptions)).current

  const search = useRef(
    debounce((value) => {
      const res =
        value === '' ? items : fuse.search(value).map((val) => val.item)
      // potential performance gain from using refIndex instead
      // and just showing/hiding cards
      setDisplayedItems(res)
    }, 100)
  ).current

  const onSearchAction = useRef((e) => {
    setPattern(e.target.value)
    search(e.target.value)
  }).current

  return (
    <motion.div initial='initial' animate='animate'>
      <SearchBar mb={3} onChange={onSearchAction} value={pattern} />
      <motion.div variants={fadeInUp({ y: 50 })}>
        <Grid
          {...props}
          sx={{
            gridTemplateColumns: [
              'repeat(auto-fill, minmax(250px, 1fr))', // better way to do this?
              null,
              'repeat(auto-fill, minmax(300px, 1fr))',
            ],
          }}
        >
          {displayedItems.map((obj, i) => (
            <Card key={i} {...obj}></Card>
          ))}
        </Grid>
      </motion.div>
    </motion.div>
  )
}

export default CardGrid
